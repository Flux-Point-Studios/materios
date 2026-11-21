"""Tests for the mainnet launch preflight.

The preprod v6 fixture is the raw chain spec the preprod network publishes; its
genesis hash was read from a live node, so the genesis-hash test checks this
implementation against the reference one. Cardano is served by a local HTTP
server that answers with Kupo's response shapes.
"""
import ast
import base64
import contextlib
import copy
import dataclasses
import gzip
import hashlib
import itertools
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import base58
import cbor2
import coincurve
import pytest
import sr25519
import xxhash
import zstandard
from nacl import signing

import capture_environ
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


# The public key table, as a check loads it when no operator table is given.
KNOWN = lp.load_well_known()
# The tables less the retired preprod keys, for the tests that seat preprod's authors as stand-ins for fresh keys.
PUBLIC_KNOWN = lp.WellKnown({needle: key for needle, key in KNOWN.keys.items() if key.label != "retired preprod key"},
                            KNOWN.phrase_hash, KNOWN.seed_hash)


@pytest.fixture(scope="session")
def known():
    return KNOWN


# How to sign as the holder of each key a test generates, by its public key.
KEYHOLDERS = {}


def fresh_account() -> bytes:
    """A new sr25519 key, whose holder the tests can sign as."""
    pair = sr25519.pair_from_seed(os.urandom(32))
    KEYHOLDERS[pair[0]] = lambda message: sr25519.sign(pair, message)
    return pair[0]


def fresh_ecdsa_key() -> bytes:
    """A new ECDSA key, compressed to 33 bytes, whose holder signs as sp_core's ecdsa does: over blake2-256 of the
    message, with the recovery id after r and s."""
    secret = coincurve.PrivateKey()
    public = secret.public_key.format()
    KEYHOLDERS[public] = lambda message: secret.sign_recoverable(lp.blake2_256(message), hasher=None)
    return public


def stranger() -> bytes:
    """A key whose holder no test can sign as."""
    return sr25519.pair_from_seed(os.urandom(32))[0]


# The all-zero key, the ristretto identity, and its sr25519 signature of every message, made with no secret: R the
# identity, s zero, then schnorrkel's marker bit.
ZERO_KEY, NO_SECRET_POP = bytes(32), bytes(63) + b"\x80"


def all_zero(where: str) -> str:
    return f"[1 dev-keys] {where}: the all-zero key, whose sr25519 signature of any message needs no secret"


# ed25519's keys of small order as libsodium 1.0.20 lists them (ge25519_has_small_order, in
# src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c), each of which it refuses with either sign bit.
LIBSODIUM_SMALL_ORDER = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]
SMALL_ORDER_KEYS = sorted(key for listed in map(bytes.fromhex, LIBSODIUM_SMALL_ORDER)
                          for key in (listed, listed[:31] + bytes([listed[31] | 0x80])))
# ed25519's identity, 0x01 then 31 zero bytes. ed25519-zebra, which the node verifies ed25519 signatures with, checks
# 8·s·B = 8·R + 8·k·A, so under a key A of small order, R the identity and s zero sign every message.
SMALL_ORDER_KEY = bytes([1]) + bytes(31)
NEEDS_NO_SECRET = "signature of any message needs no secret"


def small_order(key: bytes) -> str:
    return f"0x{key.hex()}, an ed25519 key of small order, whose ed25519 {NEEDS_NO_SECRET}"


# What anyone signing as each kind of authority key can do.
AUTHORITY_POWERS = {"aura": "anyone can author its slots", "grandpa": "anyone can cast its finality votes"}


def no_secret_authority(where: str, kind: str, key: bytes) -> str:
    reason = f"the all-zero key, whose sr25519 {NEEDS_NO_SECRET}" if kind == "aura" else small_order(key)
    return f"[1 dev-keys] {where}: {reason}, so {AUTHORITY_POWERS[kind]}"


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


def role_key(key: bytes) -> str:
    """A role key as a manifest gives it: SS58 for a 32-byte key, 0x-hex for a 33-byte ECDSA key."""
    return ss58(key) if len(key) == 32 else "0x" + key.hex()


def msig(threshold, *members) -> dict:
    return {"threshold": threshold, "members": [role_key(m) for m in members]}


POP_DOMAIN = b"materios-launch-pop-v2"
GENESIS_CONTENT_DOMAIN = b"materios-launch-genesis-content-v1"
# What a proof of possession binds of a launch manifest, listed here apart from the preflight's classification: the
# fields the chain spec is built from, whole; the lock's address and script; and of each authority its keys and the
# sha256 of its node binary.
GENESIS_BOUND = ("dust", "attestation_threshold", "economics", "partner_chain", "slots_per_epoch", "settlement",
                 "cardano_follower", "later_signers", "no_standby")
LOCK_BOUND = ("address", "native_script")
AUTHORITY_BOUND = ("authority", "aura", "grandpa", "cross_chain", "exe_sha256")


def canonical_json(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unproven_entry(entry):
    if isinstance(entry, dict) and "members" in entry:
        return dict(entry, members=[unproven_entry(member) for member in entry["members"]])
    return {"key": entry["key"]} if isinstance(entry, dict) else entry


def genesis_content_hash(launch: dict) -> bytes:
    """blake2-256 of the domain and the canonical JSON of what a proof binds of the manifest, built here apart from
    the preflight: no pop, no node that is no authority, the authorities in the order of their canonical JSON."""
    content = {field: launch[field] for field in GENESIS_BOUND if field in launch}
    if "roles" in launch:
        content["roles"] = {role: [unproven_entry(entry) for entry in entries]
                            for role, entries in launch["roles"].items()}
    lock = {field: value for field, value in launch.get("supply", {}).get("genesis_lock", {}).items()
            if field in LOCK_BOUND}
    if lock:
        content["supply"] = {"genesis_lock": lock}
    authorities = [{field: node[field] for field in AUTHORITY_BOUND if field in node}
                   for node in launch.get("nodes", []) if node.get("authority") is True]
    if authorities:
        content["nodes"] = sorted(authorities, key=canonical_json)
    return hashlib.blake2b(GENESIS_CONTENT_DOMAIN + canonical_json(content), digest_size=32).digest()


def scale_text(text: str) -> bytes:
    return lp.compact(len(text.encode())) + text.encode()


def launch_context(spec: lp.Spec, launch: dict) -> bytes:
    """What every proof of possession of a launch signs first, built here apart from the preflight: the domain, the
    chain spec's name and id, the genesis hash and the hash of the manifest's genesis-bound content."""
    return (POP_DOMAIN + scale_text(spec.doc["name"]) + scale_text(spec.doc["id"]) + lp.spec_genesis_hash(spec)
            + genesis_content_hash(launch))


def member_challenge(context: bytes, role: str, position: tuple[int, ...], key: bytes) -> bytes:
    """The challenge the holder of the member at `position` in `role` signs: the launch's context, the role, its
    multisig's index in the role and its index in each multisig down to it, each a u32, then its key as SCALE
    bytes."""
    return (context + scale_text(role) + lp.compact(len(position))
            + b"".join(index.to_bytes(4, "little") for index in position) + lp.compact(len(key)) + key)


def member_key(launch: dict, role: str, position: tuple[int, ...]) -> bytes:
    return next(lp.decode_public_key(lp.key_text(leaf)) for member_role, _, at, leaf in lp.multisig_members(launch)
                if (member_role, at) == (role, position))


def challenge(spec: lp.Spec, launch: dict, role: str, position: tuple[int, ...], key: bytes | None = None) -> bytes:
    """The challenge of the member at `position` in `role`, or what one of `key` would sign there."""
    return member_challenge(launch_context(spec, launch), role, position, key or member_key(launch, role, position))


def held(text) -> bytes | None:
    """The key a member names, when a test can sign as its holder."""
    try:
        key = lp.decode_public_key(text)
    except ValueError:
        return None
    return key if key in KEYHOLDERS else None


def prove(launch: dict, spec: lp.Spec) -> dict:
    """The launch with each multisig member whose holder a test can sign as given with that holder's proof of
    possession, as the ceremony collects them: a bare key becomes {"key": ...}, which fixes the launch manifest hash,
    and each holder then signs its challenge. A member no test holds stays as it is."""
    proven, owed = copy.deepcopy(launch), []

    def collect(multisig: dict, role: str, position: tuple[int, ...]) -> None:
        for j, member in enumerate(multisig["members"]):
            if lp.is_multisig(member):
                collect(member, role, (*position, j))
            elif isinstance(member, str) and held(member):
                multisig["members"][j] = {"key": member}
                owed.append((role, (*position, j), multisig["members"][j]))
            elif isinstance(member, dict) and "pop" not in member and held(member["key"]):
                owed.append((role, (*position, j), member))

    for role, entries in proven["roles"].items():
        for i, entry in enumerate(entries):
            if lp.is_multisig(entry):
                collect(entry, role, (i,))
    context = launch_context(spec, proven)
    for role, position, leaf in owed:
        key = held(leaf["key"])
        leaf["pop"] = "0x" + KEYHOLDERS[key](member_challenge(context, role, position, key)).hex()
    return proven


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
    keys = known.keys.values()
    table = {(k.label, k.scheme): k.needle.hex() for k in keys}
    for label, public in SP_KEYRING[scheme].items():
        assert table[(label, scheme)] == public


def test_table_holds_published_ecdsa_alice_and_its_account(known):
    keys = known.keys.values()
    needles = {k.needle.hex(): str(k) for k in keys}
    assert needles[ALICE_ECDSA] == "//Alice (ecdsa)"
    account = hashlib.blake2b(bytes.fromhex(ALICE_ECDSA), digest_size=32).hexdigest()
    assert needles[account] == "//Alice (ecdsa)"


def test_table_holds_retired_published_keys(known):
    keys = known.keys.values()
    retired = [k for k in keys if k.label == "retired validator key, mnemonic published on-chain"]
    assert {k.scheme for k in retired} == {"sr25519", "ed25519"}


# orynq-sdk commits this observer's seed as a test fixture; its SS58 is published next to it.
ORYNQ_TEST_OBSERVER = "5CfCr47V5Dte6bwxNBE8K9oNnQd9fiay6aDEEkgYtFv7w4Fq"


def test_table_holds_keys_whose_seed_is_committed_to_a_public_repo(known):
    keys = known.keys.values()
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
    keys = known.keys.values()
    table = {(k.scheme, k.needle.hex()): k.label for k in keys}
    for scheme, public in PARTNER_CHAINS_KEYSTORE.items():
        assert table[(scheme, public)] == "partner-chains test key, secret committed to a public repo"


# partner-chains commits its local environment's Cardano keys; this is the
# verification key committed next to its funded address's signing key.
PARTNER_CHAINS_CARDANO_KEY = "fc014cb5f071f5d6a36cb5a7e5f168c86555989445a23d4abec33d280f71aca4"


def test_table_holds_cardano_signing_keys_a_public_repo_commits(known):
    table = {(k.scheme, k.needle.hex()): k.label for k in known.keys.values()}
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
    keys = known.keys.values()
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
    keys = known.keys.values()
    table = {(k.label, k.scheme): k.needle.hex() for k in keys if len(k.needle) != 32 or k.scheme != "ecdsa"}
    for (path, scheme), public in NUMERIC_DEV_PATHS.items():
        assert table[(path, scheme)] == public, (path, scheme)


# Hardhat and Anvil's first test account (address 0xf39F...2266): its secret is in
# their documentation and in orynq-sdk's tests.
HARDHAT_ACCOUNT_0 = "038318535b54105d4a7aae60c08fc45f9687181b4fdfc625bd1a753fa7397fed75"


def test_table_holds_the_hardhat_test_account(known):
    keys = known.keys.values()
    hits = [k for k in keys if k.needle.hex() == HARDHAT_ACCOUNT_0]
    assert [k.scheme for k in hits] == ["ecdsa"]
    assert "public repo" in hits[0].label


# RFC 9496, Appendix A.1: ristretto255's generator, sr25519's basepoint, times 1 to 15.
RISTRETTO_MULTIPLES = [
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
]
# SEC 2, section 2.4.1: secp256k1's generator G, compressed.
SECP256K1_G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
SMALL_SCALARS = range(1, 1025)


# partner-chains commits the seeds of ECDSA scalars 1 and 513 to 517 as test keys, and the table names a key by the
# first row that holds it.
PARTNER_CHAINS_SCALARS = {1, 513, 514, 515, 516, 517}
PARTNER_CHAINS_TEST_KEY = "partner-chains test key, secret committed to a public repo"


def test_table_holds_the_published_small_multiples_of_each_generator(known):
    for k, public in enumerate(RISTRETTO_MULTIPLES, 1):
        assert str(known.keys[bytes.fromhex(public)]) == f"secret scalar {k}, public (sr25519)"
    assert str(known.keys[bytes.fromhex(SECP256K1_G)]) == f"{PARTNER_CHAINS_TEST_KEY} (ecdsa)"


def secret_scalar(k: int) -> bytes:
    """An sr25519 secret key of scalar k, as py-sr25519-bindings reads one: the scalar, then a nonce."""
    return k.to_bytes(32, "little") + bytes(32)


def test_table_holds_every_small_scalar_key_and_its_ecdsa_account(known):
    for k in SMALL_SCALARS:
        ecdsa_key = coincurve.PrivateKey.from_int(k).public_key.format()
        label = f"secret scalar {k}, public"
        ecdsa_label = PARTNER_CHAINS_TEST_KEY if k in PARTNER_CHAINS_SCALARS else label
        assert str(known.keys[sr25519.public_from_secret_key(secret_scalar(k))]) == f"{label} (sr25519)"
        for needle in (ecdsa_key, lp.blake2_256(ecdsa_key)):
            assert str(known.keys[needle]) == f"{ecdsa_label} (ecdsa)"


# The keys of mini-secrets of one repeated byte, as subkey 20.0.0 inspects them; secp256k1 takes neither 0 nor
# 0xff..ff as a secret key, so only 0x01*32 has an ECDSA key.
TRIVIAL_SEED_KEYS = {
    ("00", "sr25519"): "def12e42f3e487e9b14095aa8d5cc16a33491f1b50dadcf8811d1480f3fa8627",
    ("00", "ed25519"): "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    ("01", "sr25519"): "189dac29296d31814dc8c56cf3d36a0543372bba7538fa322a4aebfebc39e056",
    ("01", "ed25519"): "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    ("01", "ecdsa"): "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
    ("ff", "sr25519"): "48016d8d7f20ddd9774f5cc776ee0547f92b92175e58434a26d0690fbfca745a",
    ("ff", "ed25519"): "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
}


def test_table_holds_the_keys_of_trivial_mini_secrets(known):
    for (byte, scheme), public in TRIVIAL_SEED_KEYS.items():
        assert str(known.keys[bytes.fromhex(public)]) == f"mini-secret 0x{byte}*32, public ({scheme})"
    assert {(k.label, k.scheme) for k in known.keys.values() if k.label.startswith("mini-secret")} == {
        (f"mini-secret 0x{byte}*32, public", scheme) for byte, scheme in TRIVIAL_SEED_KEYS}


def test_the_public_table_lists_each_secrets_key_under_every_scheme(known):
    """A phrase or seed derives a key under each scheme, and the holder of an exposed one can sign under any: so
    every label of the public table that names a secret lists its sr25519, ed25519 and ECDSA keys. The exceptions:
    a small scalar is a secret key of sr25519 and of secp256k1 alone, a mini-secret of 0x00 or 0xff bytes is no
    secp256k1 secret, and the retired validator key's rows are the public keys it ran under: the table's generator
    holds no secret of it, so it derives no ECDSA key for it."""
    table = json.loads((HERE / "well_known_keys.json").read_text())["keys"]
    schemes: dict[str, set[str]] = {}
    for row in table:
        schemes.setdefault(row["label"], set()).add(row["scheme"])
    partial = {label: sorted(found) for label, found in schemes.items()
               if found != {"sr25519", "ed25519", "ecdsa"} and not label.startswith("secret scalar ")}
    assert partial == {"retired validator key, mnemonic published on-chain": ["ed25519", "sr25519"],
                       "mini-secret 0x00*32, public": ["ed25519", "sr25519"],
                       "mini-secret 0xff*32, public": ["ed25519", "sr25519"]}
    assert len(schemes) - len(partial) - sum(label.startswith("secret scalar ") for label in schemes) == 122
    assert all(found <= {"sr25519", "ecdsa"} for label, found in schemes.items() if label.startswith("secret scalar "))


@pytest.mark.parametrize("after", [0, 1, lp.BLOCK - 1])
@pytest.mark.parametrize("before", range(2 * lp.BLOCK))
def test_a_table_key_is_found_wherever_data_holds_it(known, before, after):
    """The block index finds what a scan for each key finds, at every alignment and up to the end of the data."""
    for needle in (ALICE, bytes.fromhex(ALICE_ECDSA), lp.blake2_256(bytes.fromhex(ALICE_ECDSA))):
        data = os.urandom(before) + needle + os.urandom(after)
        assert {k.needle for k in known.found_in(data)} == {k for k in known.keys if k in data} == {needle}


def test_the_small_order_ed25519_keys_are_libsodiums_list_with_either_sign_bit():
    assert sorted(lp.ED25519_SMALL_ORDER) == SMALL_ORDER_KEYS
    assert len(SMALL_ORDER_KEYS) == 14


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

SPEC244_RAW = FIXTURES / "preprod-spec244-raw.json"
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
    """The spec 244 raw spec as a file, its raw storage edited by `edit`."""
    doc = json.loads(SPEC244_RAW.read_text())
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
    doc = json.loads(SPEC244_RAW.read_text())
    doc["genesis"]["raw"]["top"] = {"@": ""}
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc).replace('{"@": ""}', "{" + entries + "}"))
    with pytest.raises(lp.InputError, match=re.escape(error)):
        lp.load_spec(str(path))


def test_a_spec_that_repeats_any_key_is_an_input_error(tmp_path):
    """The node refuses a field given twice; the preflight would read the last."""
    path = tmp_path / "raw.json"
    path.write_text(SPEC244_RAW.read_text().replace('"chainType": "Live"', '"chainType": "Local", "chainType": "Live"'))
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
    doc = json.loads(SPEC244_RAW.read_text())
    child = "0x" + b":child_storage:default:a".hex()
    doc["genesis"]["raw"]["childrenDefault"] = {child: {"0x00 ": "0x 01"}}
    path = tmp_path / "raw.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(lp.InputError, match="chain spec has child tries"):
        lp.load_spec(str(path))


@pytest.mark.parametrize("name", ["preprod-v6-raw.json.gz", "preprod-spec244-raw.json"])
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


def test_build_spec_output_stores_each_number_the_preflight_reads_at_the_width_of_its_type(spec, spec244):
    """Every account is an 80-byte AccountInfo filed under its own key, and
    what the accounts hold, free plus reserved, is TotalIssuance."""
    for genesis in (spec, spec244[0]):
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


@pytest.mark.parametrize("spelling", [ss58, lambda key: "0x" + key.hex()], ids=["SS58", "0x-hex"])
def test_the_all_zero_key_is_refused_in_any_role_at_any_depth(spec, meta, known, spelling):
    zero, sudo = spelling(ZERO_KEY), nested_multisig()
    sudo["members"][2]["members"][1] = {"key": zero, "pop": "0x" + NO_SECRET_POP.hex()}
    launch = {"roles": {"anchor_signer": [zero], "sudo": [sudo],
                        "endowed": [{"threshold": 1, "members": [ss58(fresh_account()), zero]}]}}
    zeros = ["roles.anchor_signer[0]", "roles.endowed[0].members[1]", "roles.sudo[0].members[2].members[1]"]
    found = dev_key_findings(spec, meta, known, launch)
    assert [m for m in found if any(m.startswith(f"[1 dev-keys] {where}:") for where in zeros)] == [
        all_zero(where) for where in zeros]


def short_hex(key: bytes) -> str:
    return f"{key[:4].hex()}..{key[-1:].hex()}"


# Any account signs with ed25519 too (MultiSignature), so an account that is an ed25519 key of small order is one
# anyone can sign as.
@pytest.mark.parametrize("key", [key for key in SMALL_ORDER_KEYS if key != ZERO_KEY], ids=short_hex)
def test_an_ed25519_key_of_small_order_is_refused_in_any_role_at_any_depth(spec, meta, known, key):
    sudo = nested_multisig()
    sudo["members"][2]["members"][1] = ss58(key)
    launch = {"roles": {"anchor_signer": ["0x" + key.hex()], "sudo": [sudo]}}
    found = dev_key_findings(spec, meta, known, launch)
    assert [m for m in found if NEEDS_NO_SECRET in m] == [
        f"[1 dev-keys] {where}: {small_order(key)}, so anyone can sign as its account"
        for where in ("roles.anchor_signer[0]", "roles.sudo[0].members[2].members[1]")]


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
        {"name": "v1", "host": "h1", "authority": False,
         "argv": ["materios-node", "--validator", "--alice", "--chain", "mainnet.json"]},
        {"name": "v2", "host": "h2", "authority": False, "argv": ["materios-node", "--dev"]},
        {"name": "cd", "host": "h3", "authority": False, "argv": [], "env": {"SIGNER_URI": "//Ferdie"}},
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
        {"name": "aw", "host": "h1", "authority": False, "argv": ["anchor-worker", "--suri", "//AnchorSigner"],
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
        {"name": "aw", "host": "h1", "authority": False, "argv": ["worker", "--suri=//Alice///s3cret"],
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
    launch = {"roles": {}, "nodes": [{"name": "v1", "host": "h1", "authority": False, "argv": [],
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


BASEPOINT, TWICE_BASEPOINT = (bytes.fromhex(public) for public in RISTRETTO_MULTIPLES[:2])


def helped_holder(rule: str, where: str, key: bytes, path: str, public: list[str], power: str) -> str:
    return (f"[{rule}] {where}: {ss58(key)}, the member at {where}.{path}, meets its threshold alone with the keys "
            f"anyone can sign as, at {' and '.join(f'{where}.{p}' for p in public)}, so one keyholder alone {power}")


def test_sudo_multisig_one_key_meets_with_a_key_anyone_holds_is_refused(spec, meta, known):
    holder = fresh_account()
    assert sudo_findings(spec, meta, known, msig(2, holder, BASEPOINT)) == [
        "[1 dev-keys] roles.sudo[0].members[1]: secret scalar 1, public (sr25519)",
        helped_holder("1 dev-keys", "roles.sudo[0]", holder, "members[0]", ["members[1]"], SUDO_POWER)]


def test_sudo_multisig_one_key_meets_with_an_ed25519_key_of_small_order_is_refused(spec, meta, known):
    holder = fresh_account()
    assert sudo_findings(spec, meta, known, msig(2, holder, SMALL_ORDER_KEY)) == [
        f"[1 dev-keys] roles.sudo[0].members[1]: {small_order(SMALL_ORDER_KEY)}, so anyone can sign as its account",
        helped_holder("1 dev-keys", "roles.sudo[0]", holder, "members[0]", ["members[1]"], SUDO_POWER)]


# frame_system's CheckNonZeroSender refuses the all-zero account as a signer, so it approves nothing: the other
# member does not meet the threshold alone.
def test_the_all_zero_member_signs_for_no_one(spec, meta, known):
    assert sudo_findings(spec, meta, known, msig(2, fresh_account(), ZERO_KEY)) == [
        all_zero("roles.sudo[0].members[1]")]


def test_sudo_multisig_that_keys_anyone_holds_meet_is_refused(spec, meta, known):
    entry = msig(2, BASEPOINT, fresh_account(), TWICE_BASEPOINT)
    assert sudo_findings(spec, meta, known, entry) == [
        "[1 dev-keys] roles.sudo[0].members[0]: secret scalar 1, public (sr25519)",
        "[1 dev-keys] roles.sudo[0].members[2]: secret scalar 2, public (sr25519)",
        "[1 dev-keys] roles.sudo[0]: the keys anyone can sign as, at roles.sudo[0].members[0] and "
        "roles.sudo[0].members[2], meet its threshold, so anyone holds Root"]


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

def cross_chain_of(aura: bytes) -> bytes:
    """The partner-chain key the tests give the authority whose aura key is `aura`, a compressed ECDSA key, so a
    launch, a genesis committee and a Cardano candidate built apart from each other name one key for it."""
    return coincurve.PrivateKey(lp.blake2_256(b"cross-chain" + aura)).public_key.format()


def candidate(aura: bytes, gran: bytes | None = None, sidechain: bytes | None = None) -> lp.Candidate:
    return lp.Candidate(sidechain or cross_chain_of(aura), aura, gran or fresh_account())


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


def authority(argv, host="val1", name="val1", aura=None, cross_chain=None):
    return {"name": name, "host": host, "authority": True, "aura": "0x" + (aura or fresh_account()).hex(),
            "grandpa": "0x" + fresh_account().hex(), "cross_chain": "0x" + (cross_chain or cross_chain_key()).hex(),
            "argv": argv, "exe_sha256": "0x" + hashlib.sha256(b"materios-node").hexdigest()}


def declared(argv, is_authority: bool, **fields) -> dict:
    """A node that runs `argv`, declared an authority, which pins its node binary, or not."""
    node = dict(authority(argv), authority=is_authority, **fields)
    if not is_authority:
        del node["exe_sha256"], node["cross_chain"]
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
    """A compressed ECDSA public key: a parity byte, then the x of a point on secp256k1."""
    return coincurve.PrivateKey().public_key.format()


def genesis_members(spec: lp.Spec) -> list[tuple[bytes, bytes, bytes]]:
    """The preprod genesis authors as committee members: each one's cross-chain key, then its aura and grandpa
    keys."""
    return [(cross_chain_of(aura), aura, gran) for aura, gran in zip(aura_keys(spec), grandpa_keys(spec))]


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
    return rpc_launch([dict(authority(["materios-node"], f"val{i}", f"val{i}", aura, cross_chain),
                            grandpa="0x" + gran.hex())
                       for i, (cross_chain, aura, gran) in enumerate(members)] + list(extra))


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


# ---------------------------------------------------------------------------
# Rule 1: authority keys anyone can sign for
# ---------------------------------------------------------------------------

def with_key(members, kind: str, key: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """The members, with the first one's aura or grandpa key replaced by `key`."""
    cross_chain, aura, gran = members[0]
    return [(cross_chain, key, gran) if kind == "aura" else (cross_chain, aura, key), *members[1:]]


def write_aura_authorities(spec, launch, cardano, members) -> None:
    put(spec, "Aura", "Authorities", lp.compact(len(members)) + b"".join(aura for _, aura, _ in members))


def write_grandpa_authorities(spec, launch, cardano, members) -> None:
    put(spec, "Grandpa", "Authorities", grandpa_list(*((gran, 1) for _, _, gran in members)))


def write_committee(spec, launch, cardano, members) -> None:
    put(spec, "SessionCommitteeManagement", "CurrentCommittee", committee_value(members))


def write_session(spec, launch, cardano, members) -> None:
    put(spec, "Session", "ValidatorsAndKeys", session_value(members))


def write_nodes(spec, launch, cardano, members) -> None:
    for node, (_, aura, gran) in zip(launch["nodes"], members):
        node.update(aura="0x" + aura.hex(), grandpa="0x" + gran.hex())


def write_candidates(spec, launch, cardano, members) -> None:
    cardano.candidates[:] = [lp.Candidate(*member) for member in members]


# Each place that holds authority keys, in the order rule 1 reads them: how to write the members' keys there, and
# how a finding names the first member's aura or grandpa key there.
AUTHORITY_PLACES = {
    "Aura.Authorities": (write_aura_authorities, {"aura": "genesis Aura.Authorities[0]"}),
    "Grandpa.Authorities": (write_grandpa_authorities, {"grandpa": "genesis Grandpa.Authorities[0]"}),
    "CurrentCommittee": (write_committee, {kind: f"{COMMITTEE}[0] {kind} key" for kind in AUTHORITY_POWERS}),
    "ValidatorsAndKeys": (write_session,
                          {kind: f"genesis Session.ValidatorsAndKeys[0] {kind} key" for kind in AUTHORITY_POWERS}),
    "nodes": (write_nodes, {kind: f"authority val0's {kind} key" for kind in AUTHORITY_POWERS}),
    "candidates": (write_candidates, {"aura": "Cardano permissioned candidate 0 aura",
                                      "grandpa": "Cardano permissioned candidate 0 gran"}),
}
NO_SECRET_KEYS = {"aura": ZERO_KEY, "grandpa": SMALL_ORDER_KEY}
FRESH_KEYS = {"aura": fresh_account, "grandpa": lambda: signing.SigningKey.generate().verify_key.encode()}


# How rule 1 names each place that holds authority keys.
AUTHORITY_PLACE_NAMES = ("genesis Aura.Authorities[", "genesis Grandpa.Authorities[", f"{COMMITTEE}[",
                         "genesis Session.ValidatorsAndKeys[", "authority ", "Cardano permissioned candidate ")


def authority_key_findings(seated, meta, write, members) -> list[str]:
    """Rule 1's findings about authority keys on the seated genesis, its launch and Cardano candidates of its
    authorities, once `members` are written in one place."""
    spec, seated_members, launch = seated
    cardano = lp.CardanoView(lock=None, candidates=[lp.Candidate(*member) for member in seated_members],
                             d_parameter=(len(seated_members), 0))
    write(spec, launch, cardano, members)
    return [m for m in dev_key_findings(spec, meta, PUBLIC_KNOWN, launch, cardano=cardano)
            if m.startswith(tuple(f"[1 dev-keys] {name}" for name in AUTHORITY_PLACE_NAMES))]


@pytest.mark.parametrize("anyone", [True, False], ids=["no-secret key", "fresh key"])
@pytest.mark.parametrize("place, kind", [(place, kind) for place, (_, named) in AUTHORITY_PLACES.items()
                                         for kind in named])
def test_an_authority_key_anyone_can_sign_for_is_refused_where_it_sits(seated, meta, place, kind, anyone):
    key = NO_SECRET_KEYS[kind] if anyone else FRESH_KEYS[kind]()
    write, named = AUTHORITY_PLACES[place]
    assert authority_key_findings(seated, meta, write, with_key(seated[1], kind, key)) == (
        [no_secret_authority(named[kind], kind, key)] if anyone else [])


@pytest.mark.parametrize("key", SMALL_ORDER_KEYS, ids=short_hex)
def test_every_ed25519_key_of_small_order_is_refused_as_a_grandpa_voter(seated, meta, key):
    assert authority_key_findings(seated, meta, write_grandpa_authorities, with_key(seated[1], "grandpa", key)) == [
        no_secret_authority("genesis Grandpa.Authorities[0]", "grandpa", key)]


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
        "once, under its own key",
        f"[9 committee] {COMMITTEE}[1] cross-chain key 0x{members[0][0].hex()} is not the cross_chain key authority "
        "val1 declares: genesis seats it under a partner-chain key no declared authority holds, and files its session "
        "keys under that key's account"]


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


def test_build_spec_starts_grandpa_at_set_0_in_session_0(spec, spec244):
    """What pallet_grandpa's genesis writes in both preprod genesis: the set id 0 as a u64, and the one SetIdSession
    entry, set 0 beginning in session 0 (a u32)."""
    prefix = lp.storage_key("Grandpa", "SetIdSession")
    for genesis in (spec, spec244[0]):
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
# What a mainnet authority's unit gives its node: those settings, its follower's backend, database and stability
# margin, and the 32 bytes its blocks are counted under. The database is declared as the capture tool reduces the
# connection string the node runs with: host, port and database, no user and no password.
AUTHORITY_ENV = {**MAINNET_FOLLOWER, "MAIN_CHAIN_FOLLOWER": "db-sync", "BLOCK_STABILITY_MARGIN": "0",
                 "DB_SYNC_POSTGRES_CONNECTION_STRING": "db-1.internal:5432/cexplorer",
                 "SIDECHAIN_BLOCK_BENEFICIARY": "0x" + "ab" * 32}


def environ_block(settings: dict) -> bytes:
    """/proc/<pid>/environ: each NAME=value ended by a NUL."""
    return b"".join(f"{name}={value}".encode() + b"\0" for name, value in settings.items())
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


# The Cardano mainnet slot the tests' Kupo is at, in epoch 600, and the one its outputs were created at, in epoch 590.
KUPO_TIP = 4_492_800 + (600 - 208) * 432_000 + 1_000
# When Cardano mainnet's Shelley era began, slot 4,492,800, in seconds since the Unix epoch: a slot is a second.
SHELLEY_START = 1_596_059_091


# The preflight's own clock, before any test sets one.
HOST_CLOCK = getattr(lp, "wall_clock", None)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """The clock of the host a check runs on reads five seconds after the tip the test Kupo serves, unless a test
    sets it."""
    monkeypatch.setattr(lp, "wall_clock", lambda: SHELLEY_START + KUPO_TIP - 4_492_800 + 5, raising=False)
CREATED = 4_492_800 + (590 - 208) * 432_000


def kupo_output(address=SCRIPT_ADDRESS, assets=None, tx=LOCK_TX, index=1, datum_hash=None) -> dict:
    """An unspent output as Kupo's /matches returns it."""
    return {"transaction_index": 0, "transaction_id": tx, "output_index": index, "address": address,
            "value": {"coins": 2_000_000, "assets": assets or {}},
            "datum_hash": datum_hash, "datum_type": "inline" if datum_hash else None, "script_hash": None,
            "created_at": {"slot_no": CREATED, "header_hash": "00" * 32}, "spent_at": None}


def locked(amount, address=SCRIPT_ADDRESS, unit=lp.CMATRA_UNIT) -> lp.CardanoView:
    return lp.CardanoView(lock=kupo_output(address, {unit: amount}), candidates=[], d_parameter=(0, 0))


def with_constants(metadata_v14: dict) -> dict:
    """The fixture metadata plus the u128 validator reward per era a runtime that declares it exposes."""
    v14 = copy.deepcopy(metadata_v14)
    pallet = next(p for p in v14["pallets"] if p["name"] == "OrinqReceipts")
    pallet["constants"] = list(pallet.get("constants") or []) + [
        {"name": "ValidatorRewardPerEra", "value": list(VALIDATOR_REWARD_PER_ERA.to_bytes(16, "little"))}]
    return v14


def issuance_of(spec) -> int:
    return int.from_bytes(spec.value("Balances", "TotalIssuance"), "little")


def supply_findings(spec, meta, cardano=None, lock=LOCK):
    """Rule 4 on a genesis whose lock holds more than any issuance, for a launch that declares nothing else."""
    if cardano is None:
        cardano = locked(10**30)
    return messages(lp.check_supply(spec, meta, {"roles": {}, "supply": {"genesis_lock": lock}}, cardano))


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
    found = supply_findings(spec, runtime_meta, cardano)
    assert any("against 0 cMATRA locked on Cardano" in m for m in found)


def test_issuance_below_what_genesis_accounts_hold_is_refused(spec, runtime_meta):
    held = issuance_of(spec)
    put(spec, "Balances", "TotalIssuance", (1).to_bytes(16, "little"))
    found = supply_findings(spec, runtime_meta)
    assert f"[4 supply] Balances.TotalIssuance stores 1, but genesis accounts hold {held}" in found


def test_missing_issuance_is_refused_and_accounts_still_count(spec, runtime_meta):
    held = issuance_of(spec)
    del spec.storage[lp.storage_key("Balances", "TotalIssuance")]
    found = supply_findings(spec, runtime_meta)
    assert f"[4 supply] Balances.TotalIssuance stores 0, but genesis accounts hold {held}" in found


def test_reserved_balances_count_toward_issuance(spec, runtime_meta):
    account = fresh_account()
    spec.storage[account_key(account)] = bytes(32) + (5 * MATRA).to_bytes(16, "little") + bytes(32)
    held = issuance_of(spec) + 5 * MATRA
    found = supply_findings(spec, runtime_meta)
    assert f"[4 supply] Balances.TotalIssuance stores {held - 5 * MATRA}, but genesis accounts hold {held}" in found


@A_BYTE_OFF
@pytest.mark.parametrize("pallet, item", [("OrinqReceipts", "BondRequirement"), ("Balances", "TotalIssuance")])
def test_a_supply_number_stored_at_another_width_is_an_input_error(spec, runtime_meta, pallet, item, change):
    """Both are u128: 16 bytes."""
    stored = int.from_bytes(spec.value(pallet, item), "little")
    put(spec, pallet, item, stored.to_bytes(16 + change, "little"))
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized(f"{pallet}.{item}", 16 + change, 16))):
        supply_findings(spec, runtime_meta)


@pytest.mark.parametrize("size", [48, 79, 81])
@pytest.mark.parametrize("whose", ["a fresh account", "another account"])
def test_an_account_stored_at_another_width_is_an_input_error(spec, runtime_meta, whose, size):
    """An account is AccountInfo<u32, AccountData<u128>>, 80 bytes: FRAME
    reads a shorter one as an empty account."""
    account = fresh_account()
    endow(spec, account, 5_000)
    key = account_key(account if whose == "a fresh account" else PREPROD_ATTESTOR)
    spec.storage[key] = (spec.storage[key] + bytes(1))[:size]
    error = mis_sized(f"System.Account value at 0x{key.hex()}", size, 80)
    with pytest.raises(lp.InputError, match="^" + re.escape(error)):
        supply_findings(spec, runtime_meta)


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
        supply_findings(spec, runtime_meta)


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


def motra_checkpoint_metadata(meta):
    for item in ("LastTouched", "AccrualCheckpoint"):
        meta.storage_names[lp.storage_key("Motra", item)] = f"Motra.{item}"
    return meta


def test_motra_genesis_rejects_even_a_zero_decay_clock(spec, meta):
    spec.storage[map_key("Motra", "LastTouched", spec.accounts()[0])] = bytes(4)
    findings = lp.check_genesis_storage(spec, motra_checkpoint_metadata(meta))
    assert any("outside the genesis allowlist" in finding.message for finding in findings)


@pytest.mark.parametrize("value", [(1).to_bytes(4, "little"), bytes(3)])
def test_motra_genesis_cannot_set_a_decay_clock(spec, meta, value):
    spec.storage[map_key("Motra", "LastTouched", spec.accounts()[0])] = value
    assert lp.check_genesis_storage(spec, motra_checkpoint_metadata(meta))


def motra_findings(spec: lp.Spec) -> list[str]:
    return messages(lp.check_motra(spec))


def checkpoint(held: int, since: int = 0) -> bytes:
    return held.to_bytes(16, "little") + since.to_bytes(4, "little")


def test_the_mainnet_fixture_checkpoints_each_endowed_account_at_its_free_balance(mainnet):
    """The Balances genesis writes a MOTRA checkpoint for every account it endows, the Treasury among them: the
    balance it holds, held since block 0."""
    spec, meta, _ = mainnet
    prefix = lp.storage_key("Motra", "AccrualCheckpoint")
    assert lp.treasury_account(meta) in spec.accounts() and len(spec.accounts()) == 23
    assert {key: value for key, value in spec.storage.items() if key.startswith(prefix)} == {
        map_key("Motra", "AccrualCheckpoint", account): checkpoint(spec.balance(account)[0])
        for account in spec.accounts()}
    assert motra_findings(spec) == []


CHECKPOINTS = [
    (lambda free: None, "sets no Motra.AccrualCheckpoint"),
    (lambda free: checkpoint(0), "checkpoints 0 MATRA base units held since block 0"),
    (lambda free: checkpoint(free - 1), "checkpoints {less} MATRA base units held since block 0"),
    (lambda free: checkpoint(free + 1), "checkpoints {more} MATRA base units held since block 0"),
    (lambda free: checkpoint(free, 1), "checkpoints {free} MATRA base units held since block 1"),
    (lambda free: checkpoint(free)[:-1], "sets a Motra.AccrualCheckpoint of 19 bytes"),
    (lambda free: checkpoint(free) + bytes(1), "sets a Motra.AccrualCheckpoint of 21 bytes"),
]


@pytest.mark.parametrize("value, shown", CHECKPOINTS, ids=[shown for _, shown in CHECKPOINTS])
def test_a_checkpoint_other_than_the_accounts_free_balance_at_block_zero_is_refused(mainnet, value, shown):
    spec, _, launch = mainnet
    account = account_of(launch["roles"]["enactor"][0])
    free = spec.balance(account)[0]
    key = map_key("Motra", "AccrualCheckpoint", account)
    if value(free) is None:
        del spec.storage[key]
    else:
        spec.storage[key] = value(free)
    assert motra_findings(spec) == [
        f"[12 dust] genesis {shown.format(free=free, less=free - 1, more=free + 1)} for {ss58(account)}, not the "
        f"{free} it holds free, held since block 0, as build-spec writes it: the runtime generates its MOTRA from "
        "the checkpoint, so it generates none, or other than its dust is sized to"]


def test_a_genesis_with_no_checkpoint_is_refused_for_every_account(mainnet):
    spec, _, _ = mainnet
    for key in [key for key in spec.storage if key.startswith(lp.storage_key("Motra", "AccrualCheckpoint"))]:
        del spec.storage[key]
    found = motra_findings(spec)
    assert len(found) == 23 and all("genesis sets no Motra.AccrualCheckpoint for " in message for message in found)


@pytest.mark.parametrize("stray", ["an account genesis does not endow", "another hash", "a longer key"])
def test_a_checkpoint_for_no_endowed_account_is_refused(mainnet, stray):
    spec, _, _ = mainnet
    account = spec.accounts()[0]
    key = {"an account genesis does not endow": map_key("Motra", "AccrualCheckpoint", fresh_account()),
           "another hash": lp.storage_key("Motra", "AccrualCheckpoint") + bytes(16) + account,
           "a longer key": map_key("Motra", "AccrualCheckpoint", account) + bytes(1)}[stray]
    spec.storage[key] = checkpoint(spec.balance(account)[0])
    assert motra_findings(spec) == [
        f"[12 dust] genesis sets the Motra.AccrualCheckpoint 0x{key.hex()}, which is not blake2_128 of an account "
        "genesis endows followed by that account: build-spec writes a checkpoint for each endowed account and no "
        "other"]


# Motra.Params as mainnet's genesis stores it, spelled out here apart from the preflight's table: a u128 minimum fee
# of 10^9, a u128 congestion rate of 0, a u32 target fullness of 500,000,000 parts per billion, a u32 share kept each
# block of 999,900,000, a u128 generation of 10^10 per MATRA per block, a u128 cap of 10^18, a u128 congestion step
# of 10^9, a u128 price per byte of 10^6 and a u32 congestion smoothing of 100,000,000.
MAINNET_MOTRA_PARAMS = bytes.fromhex(
    "00ca9a3b000000000000000000000000" "00000000000000000000000000000000" "0065cd1d" "6043993b"
    "00e40b54020000000000000000000000" "000064a7b3b6e00d0000000000000000" "00ca9a3b000000000000000000000000"
    "40420f00000000000000000000000000" "00e1f505")
MOTRA_SIZED_FOR = ("every signer's dust is sized for the fee and the generation of the mainnet parameters, min_fee "
                   "1000000000, congestion_rate 0, target_fullness 500000000, decay_rate_per_block 999900000, "
                   "generation_per_matra_per_block 10000000000, max_balance 1000000000000000000, max_congestion_step "
                   "1000000000, length_fee_per_byte 1000000, congestion_smoothing 100000000")


def test_the_mainnet_fixture_stores_the_motra_params_the_preflight_pins(mainnet):
    """The node's genesis builders name the same values: its MOTRA constants, and mainnet's generation."""
    spec, _, _ = mainnet
    assert spec.value("Motra", "Params") == MAINNET_MOTRA_PARAMS
    assert motra_findings(spec) == []
    node = HERE.parent.parent / "partnerchain" / "node" / "src"
    shared, mainnet_source = (node / "chain_spec.rs").read_text(), (node / "chain_spec_mainnet.rs").read_text()
    for declared in ("pub const MOTRA_MIN_FEE: u128 = 1_000_000_000;",
                     "pub const MOTRA_LENGTH_FEE_PER_BYTE: u128 = 1_000_000;",
                     "pub const MOTRA_KEPT_PER_BLOCK: u32 = 999_900_000;",
                     "pub const MOTRA_MAX_BALANCE: u128 = 1_000_000_000_000_000_000;",
                     '"congestionRate": 0,', '"targetFullnessPpm": 500_000_000,',
                     '"maxCongestionStep": 1_000_000_000u128,', '"congestionSmoothingPpm": 100_000_000'):
        assert declared in shared
    assert "pub const MAINNET_GENERATION_PER_MATRA_PER_BLOCK: u128 = 10_000_000_000;" in mainnet_source


MOTRA_PARAMS_EDITS = [
    (lambda raw: None, "sets no Motra.Params, which the runtime reads as all zero"),
    (lambda raw: b"", "stores a Motra.Params of 0 bytes, not the 108 its type encodes to"),
    (lambda raw: raw + bytes(1), "stores a Motra.Params of 109 bytes, not the 108 its type encodes to"),
    (lambda raw: raw[:-1] + bytes([raw[-1] ^ 1]),
     "stores Motra.Params with congestion_smoothing 83222784 for 100000000"),
    (lambda raw: raw[:40] + (10**5).to_bytes(16, "little") + raw[56:],
     "stores Motra.Params with generation_per_matra_per_block 100000 for 10000000000"),
    (lambda raw: (10**12).to_bytes(16, "little") + (1).to_bytes(16, "little") + raw[32:],
     "stores Motra.Params with min_fee 1000000000000 for 1000000000, congestion_rate 1 for 0"),
    (lambda raw: bytes(108),
     "stores Motra.Params with min_fee 0 for 1000000000, target_fullness 0 for 500000000, decay_rate_per_block 0 for "
     "999900000, generation_per_matra_per_block 0 for 10000000000, max_balance 0 for 1000000000000000000, "
     "max_congestion_step 0 for 1000000000, length_fee_per_byte 0 for 1000000, congestion_smoothing 0 for 100000000"),
]


@pytest.mark.parametrize("edit, shown", MOTRA_PARAMS_EDITS, ids=[shown[:60] for _, shown in MOTRA_PARAMS_EDITS])
def test_motra_params_other_than_mainnets_are_refused(mainnet, edit, shown):
    spec, _, _ = mainnet
    key = lp.storage_key("Motra", "Params")
    if edit(spec.storage[key]) is None:
        del spec.storage[key]
    else:
        spec.storage[key] = edit(spec.storage[key])
    assert motra_findings(spec) == [f"[12 dust] genesis {shown}: {MOTRA_SIZED_FOR}"]


@pytest.fixture
def spec244() -> tuple[lp.Spec, lp.Metadata]:
    """The preprod genesis spec 244 builds, less its :code, and that code's
    metadata trimmed to what the preflight reads. The README's Tests section
    gives the commands that build both."""
    v14 = json.loads((FIXTURES / "spec244-metadata.json").read_text())["V14"]
    return lp.load_spec(str(FIXTURES / "preprod-spec244-raw.json")), lp.Metadata.from_v14(v14)


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


def test_the_spec244_fixtures_are_the_runtime_this_source_builds(spec244):
    """The fixtures stand for the runtime this tree builds: its metadata's
    System.Version and the LastRuntimeUpgrade build-spec writes carry the spec
    and transaction versions the runtime source declares."""
    source = (HERE.parent.parent / "partnerchain" / "runtime" / "src" / "lib.rs").read_text()
    declared = [int(re.search(rf"\n\s*{field}: (\d+),", source).group(1))
                for field in ("spec_version", "transaction_version")]
    spec, meta = spec244
    name, spec_version, transaction_version = version_fields(meta.constants[("System", "Version")])
    assert (name, [spec_version, transaction_version]) == (b"\x20materios", declared)
    assert spec.value("System", "LastRuntimeUpgrade") == lp.compact(spec_version) + name


def test_every_item_the_spec244_preprod_genesis_sets_is_on_the_allowlist(spec244):
    """Rule 4 reads which items genesis sets, not what they hold: rule 7
    refuses this genesis's Root timelock delays and guardian."""
    assert lp.check_genesis_storage(*spec244) == []


def test_the_spec244_genesis_starts_settlement_at_its_current_version_settling_against_preprod(spec244):
    """build-spec writes the settlement pallet's storage version 5, both legacy cutovers at block zero, which that
    version reads as closed, so no upgrade migrates settlement and no legacy settle or expire call runs, and the
    Cardano network preprod settles against: network magic 1, preprod's Shelley genesis and no Aegis policy."""
    spec, _ = spec244
    assert spec.value("IntentSettlement", "SettlementStorageVersion") == (5).to_bytes(4, "little")
    assert spec.value("IntentSettlement", "StcaCutoverBlock") == bytes(4)
    assert spec.value("IntentSettlement", "PolicyExpireCutoverBlock") == bytes(4)
    assert lp.stored_cardano_ids(spec) == (1, CARDANO_PREPROD_SHELLEY, bytes(28))


@pytest.fixture
def mainnet() -> tuple[lp.Spec, lp.Metadata, dict]:
    """The genesis `materios-node build-spec --chain mainnet:fixtures/mainnet-launch.json --raw` writes, less its
    :code, with the metadata of the spec 244 runtime that builds it and the launch manifest it was built from. A node
    test holds the spec to what this source builds."""
    v14 = json.loads((FIXTURES / "spec244-metadata.json").read_text())["V14"]
    spec = lp.load_spec(str(FIXTURES / "mainnet-launch-raw.json"))
    spec.storage[lp.CODE_KEY] = b""
    return spec, lp.Metadata.from_v14(v14), json.loads((FIXTURES / "mainnet-launch.json").read_text())


def spec_rule_findings(spec: lp.Spec, meta: lp.Metadata, launch: dict, known, cardano=NO_CARDANO) -> list[str]:
    """Every rule that reads only the spec, its metadata and the manifest, after the manifest is read: rules 3, 6, 8
    and 10 read node captures, live RPC or signatures, and the Cardano half of rules 4 and 9 reads Kupo."""
    lp.validate_launch(launch)
    return messages(lp.check_chain_identity(spec)
                    + lp.check_dev_keys(spec, meta, launch, cardano, [], known)
                    + lp.check_attestation_committee(spec, meta, launch)
                    + lp.check_committee(spec, meta, launch)
                    + lp.check_sessions(spec, meta, launch)
                    + lp.check_follower(launch)
                    + lp.check_authority_settings(launch)
                    + lp.check_partner_chain(spec, launch)
                    + lp.check_rewards(spec, meta, launch)
                    + lp.check_supply(spec, meta, launch, cardano)
                    + lp.check_dust(spec, meta, launch)
                    + lp.check_motra(spec)
                    + lp.check_genesis_storage(spec, meta)
                    + lp.check_pinned_storage(spec, meta)
                    + lp.check_pallets(meta)
                    + lp.check_observation(spec)
                    + lp.check_code_overrides(launch)
                    + lp.check_guardian(spec, meta, launch, known)
                    + lp.check_delays(spec, meta)
                    + lp.check_settlement(spec, launch))


def test_the_mainnet_fixture_launch_passes_each_rule_that_reads_neither_cardano_nor_a_signature(mainnet, known):
    """The node builds a mainnet genesis from the launch manifest: its fixed issuance of dust, the Treasury's
    existential deposit, the attestation committee seated at genesis, each authority's partner-chain key and the
    Cardano scripts its genesis UTXO derives. Every rule that reads only the spec, its metadata and the manifest
    passes it."""
    spec, meta, launch = mainnet
    assert spec.value("Sudo", "Key") == lp.role_account(launch["roles"]["sudo"][0])
    assert spec_rule_findings(spec, meta, launch, known) == []


ED = 500
TREASURY = (b"modl" + b"mat/trsy").ljust(32, b"\0")


def test_the_mainnet_fixture_guards_the_timelock_with_the_2_of_2_the_key_kit_drives(mainnet):
    """The key kit and its coordinator hold the guardian as two keyholders who both sign: genesis names that
    multisig's account as the timelock guardian."""
    spec, _, launch = mainnet
    (guardian,) = launch["roles"]["guardian"]
    assert guardian["threshold"] == 2 and len(guardian["members"]) == 2
    assert spec.value("RootTimelock", "Guardian") == lp.role_account(guardian)


def test_the_mainnet_fixture_fixes_its_issuance_at_its_dust_and_the_treasurys_existential_deposit(mainnet):
    spec, meta, launch = mainnet
    dust = sum(amount for accounts in launch["dust"].values() for amount in accounts.values())
    assert meta.constants[("Balances", "ExistentialDeposit")] == ED.to_bytes(16, "little")
    assert lp.treasury_account(meta) == TREASURY and spec.balance(TREASURY) == (ED, 0)
    assert spec.uint("OrinqReceipts", "FixedIssuance", 16) == spec.uint("Balances", "TotalIssuance", 16) \
        == dust + ED == 977_000


def account_of(text: str) -> bytes:
    raw = base58.b58decode(text)[1:33] if not text.startswith("0x") else bytes.fromhex(text[2:])
    return lp.blake2_256(raw) if len(raw) == 33 else raw


def set_account(spec: lp.Spec, account: bytes, free: int, providers: int = 1) -> None:
    """An account as the Balances genesis writes one: a provider, its free balance and the MOTRA checkpoint of that
    balance at block 0, with the issuance and the fixed issuance moved with it."""
    old = spec.balance(account)[0]
    spec.storage[account_key(account)] = (bytes(8) + providers.to_bytes(4, "little") + bytes(4)
                                          + free.to_bytes(16, "little") + bytes(32) + (2**127).to_bytes(16, "little"))
    spec.storage[map_key("Motra", "AccrualCheckpoint", account)] = free.to_bytes(16, "little") + bytes(4)
    for pallet, item in (("Balances", "TotalIssuance"), ("OrinqReceipts", "FixedIssuance")):
        put(spec, pallet, item, (spec.uint(pallet, item, 16) + free - old).to_bytes(16, "little"))


def redust(spec: lp.Spec, launch: dict, role: str, name: str, amount: int) -> None:
    """Endow a role account `amount` in genesis and in the launch's dust alike."""
    launch["dust"].setdefault(role, {})[name] = amount
    set_account(spec, account_of(name), amount)


# ---------------------------------------------------------------------------
# The launch manifest's genesis fields
# ---------------------------------------------------------------------------

def test_a_role_no_mainnet_launch_knows_is_an_input_error(mainnet):
    _, _, launch = mainnet
    launch["roles"]["treasurer"] = [ss58(fresh_account())]
    with pytest.raises(lp.InputError, match="^roles.treasurer is not a role a mainnet launch knows: the roles are "
                                            "anchor_signer, attestors, dust_pool, enactor, endowed, gateway_sponsor, "
                                            "guardian, oracle, recovery_friends, recovery_rescuers, sudo$"):
        lp.validate_launch(launch)


@pytest.mark.parametrize("node", [0, 4], ids=["an authority", "another node"])
def test_a_node_field_no_reader_knows_is_an_input_error(mainnet, node):
    _, _, launch = mainnet
    launch["nodes"].append({"name": "edge", "host": "edge", "authority": False})
    launch["nodes"][node]["partner_chain_key"] = "0x02" + "ab" * 32
    with pytest.raises(lp.InputError, match=f"^nodes\\[{node}\\] has unknown field partner_chain_key$"):
        lp.validate_launch(launch)


PARTNER_CHAIN_UTXO = "09b6fee196c91cd2a78183f837b83f8410183edcdf1edca6e80ff7571dd7a75d"
NOT_A_GENESIS_UTXO = "^partner_chain.genesis_utxo must be <64 lowercase hex>#<output index from 0 to 32767"


@pytest.mark.parametrize("edit, error", [
    (lambda pc: pc.pop("d_parameter_policy_id"), "^partner_chain must hold exactly committee_candidate_address, "),
    (lambda pc: pc.update(genesis_lock="x"), "^partner_chain must hold exactly committee_candidate_address, "),
    (lambda pc: pc.update(genesis_utxo=7), "^partner_chain must hold exactly committee_candidate_address, "),
    (lambda pc: pc.update(genesis_utxo=f"{PARTNER_CHAIN_UTXO}#32768"), NOT_A_GENESIS_UTXO),
    (lambda pc: pc.update(genesis_utxo=f"{PARTNER_CHAIN_UTXO}#01"), NOT_A_GENESIS_UTXO),
    (lambda pc: pc.update(genesis_utxo=f"{PARTNER_CHAIN_UTXO.upper()}#0"), NOT_A_GENESIS_UTXO),
    (lambda pc: pc.update(genesis_utxo=f"{PARTNER_CHAIN_UTXO}#-1"), NOT_A_GENESIS_UTXO),
    (lambda pc: pc.update(genesis_utxo=PARTNER_CHAIN_UTXO), NOT_A_GENESIS_UTXO),
    (lambda pc: pc.update(d_parameter_policy_id="0x" + "ab" * 27),
     "^partner_chain.d_parameter_policy_id must be a 28-byte Cardano policy id$"),
    (lambda pc: pc.update(permissioned_candidates_policy_id="0x" + "AB" * 28),
     "^partner_chain.permissioned_candidates_policy_id is not 0x-prefixed lowercase hex"),
], ids=["a field missing", "an unknown field", "a number", "output 32768", "a leading zero", "upper case",
        "a negative index", "no index", "27-byte policy", "upper-case policy"])
def test_a_partner_chain_the_builder_would_not_read_is_an_input_error(mainnet, edit, error):
    _, _, launch = mainnet
    edit(launch["partner_chain"])
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch(launch)


def test_the_highest_genesis_utxo_index_partner_chains_reads_is_read(mainnet):
    _, _, launch = mainnet
    launch["partner_chain"]["genesis_utxo"] = f"{PARTNER_CHAIN_UTXO}#32767"
    lp.validate_launch(launch)


@pytest.mark.parametrize("dust, error", [
    (["5000"], "^dust must map each role to an object of accounts and the base units each holds$"),
    ({"oracle": 5000}, "^dust must map each role to an object of accounts and the base units each holds$"),
    ({"oracle": {"5ExZQnaVM2aGSNyTnNawqyDFu5TXh9Q13oTdHLVtPJN9xrfE": -1}}, "must be a u128 of base units$"),
    ({"oracle": {"5ExZQnaVM2aGSNyTnNawqyDFu5TXh9Q13oTdHLVtPJN9xrfE": True}}, "must be a u128 of base units$"),
    ({"oracle": {"5ExZQnaVM2aGSNyTnNawqyDFu5TXh9Q13oTdHLVtPJN9xrfE": "5000"}}, "must be a u128 of base units$"),
    ({"oracle": {"5ExZQnaVM2aGSNyTnNawqyDFu5TXh9Q13oTdHLVtPJN9xrfE": 2**128}}, "must be a u128 of base units$"),
    ({"oracle": {"0X" + "ab" * 32: 5000}}, "^dust.oracle account is not 0x-prefixed lowercase hex"),
])
def test_dust_the_builder_would_not_read_is_an_input_error(mainnet, dust, error):
    _, _, launch = mainnet
    launch["dust"] = dust
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch(launch)


@pytest.mark.parametrize("threshold", ["2", -1, True, 2**32, 2.0])
def test_an_attestation_threshold_that_is_not_a_u32_is_an_input_error(mainnet, threshold):
    _, _, launch = mainnet
    launch["attestation_threshold"] = threshold
    with pytest.raises(lp.InputError, match="^attestation_threshold must be a u32"):
        lp.validate_launch(launch)


NO_CROSS_CHAIN = ("^nodes\\[0\\] is an authority and must declare its cross_chain key: its ECDSA partner-chain key, 33 "
                  "bytes compressed \\(0x02 or 0x03 first, then the x of a point on secp256k1\\), as 0x-hex$")


@pytest.mark.parametrize("cross_chain, error", [
    (None, NO_CROSS_CHAIN), (7, NO_CROSS_CHAIN), ("0x02" + "ab" * 31, NO_CROSS_CHAIN),
    ("0x04" + "ab" * 32, NO_CROSS_CHAIN), ("0x00" + "ab" * 32, NO_CROSS_CHAIN),
    ("0x02" + "AB" * 32, "^nodes\\[0\\] cross_chain is not 0x-prefixed lowercase hex"),
], ids=["missing", "a number", "32 bytes", "uncompressed prefix", "zero prefix", "upper case"])
def test_an_authority_without_a_compressed_partner_chain_key_is_an_input_error(mainnet, cross_chain, error):
    _, _, launch = mainnet
    if cross_chain is None:
        del launch["nodes"][0]["cross_chain"]
    else:
        launch["nodes"][0]["cross_chain"] = cross_chain
    with pytest.raises(lp.InputError, match=error):
        lp.validate_launch(launch)


def test_a_partner_chain_key_on_a_node_that_is_no_authority_is_an_input_error(mainnet):
    _, _, launch = mainnet
    launch["nodes"].append({"name": "edge", "host": "edge", "authority": False, "cross_chain": "0x02" + "ab" * 32})
    with pytest.raises(lp.InputError, match="^nodes\\[4\\] cross_chain is read for an authority only$"):
        lp.validate_launch(launch)


# ---------------------------------------------------------------------------
# Rule 1: the Treasury, role keys and the attestation committee
# ---------------------------------------------------------------------------

def test_another_pallet_account_is_not_declared_as_the_treasury_is(mainnet, known):
    spec, meta, launch = mainnet
    pot = (b"modl" + b"mat/attr").ljust(32, b"\0")
    set_account(spec, pot, ED)
    found = spec_rule_findings(spec, meta, launch, known)
    assert f"[1 dev-keys] genesis account {ss58(pot)} is not declared in any role: who holds it is unchecked" in found
    assert not any(ss58(TREASURY) in message for message in found)


@pytest.mark.parametrize("first", [0x00, 0x04, 0x06, 0xff])
def test_a_33_byte_role_key_that_is_no_compressed_ecdsa_key_is_refused(spec, meta, known, first):
    """An oracle given as 0x00 followed by a 32-byte key reads as a 33-byte ECDSA key whose account, blake2-256 of
    those bytes, no key signs as."""
    key = bytes([first]) + fresh_account()
    launch = {"roles": {"oracle": ["0x" + key.hex()], "sudo": [msig(2, fresh_account(), key)]}}
    found = dev_key_findings(spec, meta, known, launch)
    for where in ("roles.oracle[0]", "roles.sudo[0].members[1]"):
        assert f"[1 dev-keys] {where} is 33 bytes whose first is 0x{first:02x}, not a compressed ECDSA key (0x02 or " \
               "0x03): its account is blake2-256 of bytes no ECDSA key signs as" in found


def off_curve_key(parity: int = 2) -> bytes:
    """33 bytes shaped as a compressed ECDSA key whose x is on no point of secp256k1, as coincurve reads them."""
    for counter in itertools.count():
        key = bytes([parity]) + hashlib.sha256(b"off the curve %d" % counter).digest()
        try:
            coincurve.PublicKey(key)
        except ValueError:
            return key


def test_the_preflights_curve_check_agrees_with_libsecp256k1():
    def parses(key: bytes) -> bool:
        try:
            coincurve.PublicKey(key)
        except ValueError:
            return False
        return True

    keys = [bytes([2 + i % 2]) + hashlib.sha256(b"x %d" % i).digest() for i in range(400)]
    keys += [coincurve.PrivateKey().public_key.format() for _ in range(20)]
    prime = 2**256 - 2**32 - 977
    keys += [bytes([2]) + bytes(32), bytes([3]) + bytes([255]) * 32, bytes([2]) + prime.to_bytes(32, "big"),
             bytes([2]) + (prime - 1).to_bytes(32, "big"), bytes([4]) + coincurve.PrivateKey().public_key.format()[1:],
             off_curve_key(), off_curve_key(3)]
    assert [lp.secp256k1_point(key) for key in keys] == [parses(key) for key in keys]
    assert 150 < sum(map(lp.secp256k1_point, keys[:400])) < 250
    assert not lp.secp256k1_point(off_curve_key())
    assert not lp.secp256k1_point(coincurve.PrivateKey().public_key.format()[:32])


@pytest.mark.parametrize("parity", [2, 3])
def test_a_33_byte_role_key_that_is_no_point_on_the_curve_is_refused(spec, meta, known, parity):
    """About half of all 32-byte values are the x of no point on secp256k1: 0x02 or 0x03 before one is the shape of
    a compressed key that no secret has, so its account never signs."""
    key = off_curve_key(parity)
    launch = {"roles": {"oracle": ["0x" + key.hex()], "sudo": [msig(2, fresh_account(), key)]}}
    found = dev_key_findings(spec, meta, known, launch)
    for where in ("roles.oracle[0]", "roles.sudo[0].members[1]"):
        assert f"[1 dev-keys] {where} is 33 bytes that are no point on secp256k1: its account is blake2-256 of " \
               "bytes no ECDSA key signs as" in found


def test_an_authority_whose_partner_chain_key_is_no_point_on_the_curve_is_an_input_error(mainnet):
    _, _, launch = mainnet
    launch["nodes"][0]["cross_chain"] = "0x" + off_curve_key().hex()
    with pytest.raises(lp.InputError, match=NO_CROSS_CHAIN):
        lp.validate_launch(launch)


def test_a_cardano_candidate_whose_partner_chain_key_is_no_point_on_the_curve_is_refused(mainnet):
    _, meta, launch = mainnet
    candidates = fixture_candidates(launch)
    candidates[1] = dataclasses.replace(candidates[1], partner_chains_key=off_curve_key())
    cardano = lp.CardanoView(lock=None, candidates=candidates, d_parameter=(4, 0))
    assert messages(lp.check_cardano_committee(meta, cardano)) == [
        "[9 committee] Cardano permissioned candidate 1 has a partner chains key that is no compressed secp256k1 "
        "point: no key signs as it, and once the committee is drawn from Cardano its seat is filed under an account "
        "no one holds"]


def test_a_compressed_ecdsa_role_key_is_read(spec, meta, known):
    launch = {"roles": {"oracle": ["0x" + fresh_ecdsa_key().hex()]}}
    assert not any("roles.oracle[0]" in message for message in dev_key_findings(spec, meta, known, launch))


def committee_members(*accounts: bytes) -> bytes:
    return lp.compact(len(accounts)) + b"".join(sorted(accounts))


def attestation_findings(spec, meta, launch) -> list[str]:
    return messages(lp.check_attestation_committee(spec, meta, launch))


def test_a_genesis_attestation_committee_no_role_declares_is_refused(mainnet):
    spec, meta, launch = mainnet
    outsider = fresh_account()
    attestors = [account_of(text) for text in launch["roles"]["attestors"]]
    put(spec, "OrinqReceipts", "CommitteeMembers", committee_members(outsider, *attestors[1:]))
    assert attestation_findings(spec, meta, launch) == [
        f"[1 dev-keys] genesis OrinqReceipts.CommitteeMembers seats {ss58(outsider)}, which roles.attestors does not "
        "declare: it certifies receipts unchecked",
        f"[1 dev-keys] roles.attestors[0] {launch['roles']['attestors'][0]} is not in genesis "
        "OrinqReceipts.CommitteeMembers: it certifies no receipt"]


def test_a_genesis_that_seats_no_attestation_committee_is_refused(mainnet):
    spec, meta, launch = mainnet
    for item in ("CommitteeMembers", "AttestationThreshold"):
        del spec.storage[lp.storage_key("OrinqReceipts", item)]
    assert attestation_findings(spec, meta, launch) == [
        f"[1 dev-keys] roles.attestors[{i}] {text} is not in genesis OrinqReceipts.CommitteeMembers: it certifies no "
        "receipt" for i, text in enumerate(launch["roles"]["attestors"])] + [
        "[1 dev-keys] genesis sets no OrinqReceipts.AttestationThreshold: the committee certifies no receipt"]


@pytest.mark.parametrize("stored, declared, found", [
    (3, 2, ["[1 dev-keys] genesis OrinqReceipts.AttestationThreshold is 3, not the attestation_threshold 2 the launch "
            "declares"]),
    (0, 0, ["[1 dev-keys] genesis OrinqReceipts.AttestationThreshold 0 is outside 1 to the 3 members of the "
            "committee: no receipt is certified"]),
    (4, 4, ["[1 dev-keys] genesis OrinqReceipts.AttestationThreshold 4 is outside 1 to the 3 members of the "
            "committee: no receipt is certified"]),
    (2, None, ["[1 dev-keys] the launch declares no attestation_threshold: how many attestors certify a receipt is "
               "unchecked"]),
])
def test_an_attestation_threshold_other_than_the_declared_one_in_range_is_refused(mainnet, stored, declared, found):
    spec, meta, launch = mainnet
    put(spec, "OrinqReceipts", "AttestationThreshold", stored.to_bytes(4, "little"))
    if declared is None:
        del launch["attestation_threshold"]
    else:
        launch["attestation_threshold"] = declared
    assert attestation_findings(spec, meta, launch) == found


def test_an_attestation_committee_past_the_runtimes_bound_is_refused(mainnet):
    spec, meta, launch = mainnet
    meta.constants[("OrinqReceipts", "MaxCommitteeSize")] = (2).to_bytes(4, "little")
    assert attestation_findings(spec, meta, launch) == [
        "[1 dev-keys] genesis OrinqReceipts.CommitteeMembers lists 3 attestors, and the runtime's "
        "OrinqReceipts.MaxCommitteeSize is 2: a set past it decodes as none, so no receipt is certified"]


def not_a_set(listed: int, accounts: int) -> str:
    return (f"[1 dev-keys] genesis OrinqReceipts.CommitteeMembers lists {listed} entries that are not {accounts} "
            "accounts each once in ascending order, as SCALE encodes a set and build-spec writes it: the runtime "
            "counts every listed entry against its MaxCommitteeSize and seats each account once, so the committee it "
            "reads is not the one listed")


def test_the_runtime_bounds_the_attestation_committee_at_the_size_the_fixture_metadata_declares(mainnet):
    _, meta, _ = mainnet
    source = (HERE.parent.parent / "partnerchain" / "runtime" / "src" / "lib.rs").read_text()
    assert "type MaxCommitteeSize = ConstU32<96>;" in source
    assert lp.uint_constant(meta, "OrinqReceipts", "MaxCommitteeSize", 4) == 96


def test_an_attestation_committee_that_repeats_its_members_past_the_runtimes_bound_is_refused(mainnet):
    """The runtime checks a set's listed length against MaxCommitteeSize before it drops the repeats, so 97 entries
    of the three declared attestors decode as no committee at all, where a reader that collects them into a set
    sees the three."""
    spec, meta, launch = mainnet
    members = lp.fixed_list(spec.value("OrinqReceipts", "CommitteeMembers"), 32, "the fixture's committee")
    listed = members + [members[0]] * 94
    put(spec, "OrinqReceipts", "CommitteeMembers", lp.compact(len(listed)) + b"".join(listed))
    assert attestation_findings(spec, meta, launch) == [
        not_a_set(97, 3),
        "[1 dev-keys] genesis OrinqReceipts.CommitteeMembers lists 97 attestors, and the runtime's "
        "OrinqReceipts.MaxCommitteeSize is 96: a set past it decodes as none, so no receipt is certified"]


@pytest.mark.parametrize("order, listed, accounts", [
    (lambda members: members + [members[0]], 4, 3),
    (lambda members: [members[0]] * 3, 3, 1),
    (lambda members: members[::-1], 3, 3),
    (lambda members: [members[1], members[0], members[2]], 3, 3),
], ids=["a member twice", "one member three times", "descending", "two exchanged"])
def test_an_attestation_committee_not_encoded_as_a_set_is_refused(mainnet, order, listed, accounts):
    spec, meta, launch = mainnet
    members = order(lp.fixed_list(spec.value("OrinqReceipts", "CommitteeMembers"), 32, "the fixture's committee"))
    put(spec, "OrinqReceipts", "CommitteeMembers", lp.compact(len(members)) + b"".join(members))
    found = attestation_findings(spec, meta, launch)
    assert not_a_set(listed, accounts) in found
    assert [message for message in found if "is not in genesis" not in message and "is outside 1 to" not in message] \
        == [not_a_set(listed, accounts)]


@pytest.mark.parametrize("item, value", [("BackupSigners", lambda members: members),
                                         ("BackupSigners", lambda members: lp.compact(0)),
                                         ("BackupSignerDelay", lambda members: (2**31).to_bytes(4, "little")),
                                         ("BackupSignerDelay", lambda members: bytes(4))])
def test_a_genesis_that_names_backup_signers_or_their_delay_is_refused(mainnet, known, item, value):
    """build-spec writes neither: a backup signer certifies unpaid once its delay has passed, and no role declares
    one."""
    spec, meta, launch = mainnet
    put(spec, "OrinqReceipts", item, value(spec.value("OrinqReceipts", "CommitteeMembers")))
    assert spec_rule_findings(spec, meta, launch, known) == [
        f"[4 supply] genesis sets OrinqReceipts.{item} (1 entry), which a mainnet genesis may not set: storage "
        "outside the genesis allowlist can hold a claim on MATRA that the supply check does not count"]


def test_a_runtime_that_hides_its_attestation_committee_bound_is_refused(mainnet):
    spec, meta, launch = mainnet
    del meta.constants[("OrinqReceipts", "MaxCommitteeSize")]
    assert attestation_findings(spec, meta, launch) == [
        "[1 dev-keys] the runtime metadata declares no OrinqReceipts.MaxCommitteeSize the preflight can read: whether "
        "the runtime decodes the genesis attestation committee is unknown here"]


# ---------------------------------------------------------------------------
# Rule 4: a fixed issuance of dust
# ---------------------------------------------------------------------------

def mainnet_supply(spec, meta, launch, cardano=NO_CARDANO) -> list[str]:
    return messages(lp.check_supply(spec, meta, launch, cardano))


def test_a_genesis_that_fixes_no_issuance_is_refused(spec244, mainnet):
    spec, meta, launch = mainnet
    del spec.storage[lp.storage_key("OrinqReceipts", "FixedIssuance")]
    assert mainnet_supply(spec, meta, launch) == [
        "[4 supply] genesis sets no OrinqReceipts.FixedIssuance: a genesis that does not fix its issuance lets the "
        "runtime mint its emission reserves, and a mainnet genesis issues dust that nothing adds to"]
    preprod, _ = spec244
    assert "[4 supply] genesis sets no OrinqReceipts.FixedIssuance: a genesis that does not fix its issuance lets the " \
           "runtime mint its emission reserves, and a mainnet genesis issues dust that nothing adds to" \
           in mainnet_supply(preprod, meta, launch)


def test_a_fixed_issuance_other_than_genesis_holds_is_refused(mainnet):
    spec, meta, launch = mainnet
    put(spec, "OrinqReceipts", "FixedIssuance", (977_001).to_bytes(16, "little"))
    assert mainnet_supply(spec, meta, launch) == [
        "[4 supply] OrinqReceipts.FixedIssuance stores 977001, but Balances.TotalIssuance stores 977000: the runtime "
        "holds the issuance to the fixed one",
        "[4 supply] OrinqReceipts.FixedIssuance stores 977001, not the 977000 the launch's dust and the Treasury's "
        "existential deposit sum to"]


def test_an_account_holding_other_than_its_declared_dust_is_refused(mainnet):
    spec, meta, launch = mainnet
    oracle = launch["roles"]["oracle"][0]
    set_account(spec, account_of(oracle), 55_001)
    assert mainnet_supply(spec, meta, launch) == [
        f"[4 supply] genesis endows {oracle} 55001 free and 0 reserved, but dust.oracle.{oracle} declares 55000",
        "[4 supply] OrinqReceipts.FixedIssuance stores 977001, not the 977000 the launch's dust and the Treasury's "
        "existential deposit sum to"]


def test_an_account_genesis_endows_and_no_dust_declares_is_refused(mainnet):
    spec, meta, launch = mainnet
    outsider = fresh_account()
    set_account(spec, outsider, ED)
    assert f"[4 supply] genesis endows {ss58(outsider)} 500 free and 0 reserved, but the launch's dust declares none" \
           in mainnet_supply(spec, meta, launch)


def account_info(free: int, nonce=0, consumers=0, providers=1, sufficients=0, reserved=0, frozen=0,
                 flags=2**127) -> bytes:
    """frame_system's AccountInfo over pallet_balances' AccountData: four u32 counts, then four u128."""
    return (b"".join(count.to_bytes(4, "little") for count in (nonce, consumers, providers, sufficients))
            + b"".join(amount.to_bytes(16, "little") for amount in (free, reserved, frozen, flags)))


def test_the_balances_genesis_writes_every_fixture_account_one_shape(mainnet):
    """Each of the 22 accounts the node's build endows, the Treasury among them, holds its balance free behind one
    provider, with pallet_balances' new-logic flag and nothing else."""
    spec, meta, _ = mainnet
    assert lp.treasury_account(meta) in spec.accounts()
    assert [spec.storage[account_key(account)] for account in spec.accounts()] == [
        account_info(spec.balance(account)[0]) for account in spec.accounts()]
    source = (HERE.parent.parent / "partnerchain" / "runtime" / "src" / "lib.rs").read_text()
    assert "type AccountData = pallet_balances::AccountData<Balance>;" in source
    assert lp.ACCOUNT_FLAGS == 2**127


def mis_shaped(account: bytes, nonce=0, consumers=0, providers=1, sufficients=0, frozen=0, flags=2**127) -> str:
    return (f"[4 supply] genesis System.Account of {ss58(account)} holds nonce {nonce}, consumers {consumers}, "
            f"providers {providers}, sufficients {sufficients}, frozen {frozen} and flags 0x{flags:032x}, not the "
            "nonce 0, consumers 0, providers 1, sufficients 0, frozen 0 and flags 0x80000000000000000000000000000000 "
            "the Balances genesis writes for an account it endows: a frozen balance cannot be reserved for a "
            "deposit, a nonce refuses its first calls, and a reference count nothing took keeps or drops the "
            "account apart from its balance")


ACCOUNT_SHAPES = [{"frozen": 2**128 - 1}, {"frozen": 1}, {"nonce": 7}, {"nonce": 2**32 - 1}, {"consumers": 1},
                  {"providers": 2}, {"providers": 0}, {"providers": 2**32 - 1}, {"providers": 0, "sufficients": 1},
                  {"sufficients": 5}, {"flags": 0}, {"flags": 2**128 - 1}, {"flags": 2**127 + 1}]
SHAPED_ACCOUNTS = {
    "a sudo keyholder": lambda meta, launch: lp.role_account(launch["roles"]["sudo"][0]["members"][0]),
    "the sudo account": lambda meta, launch: lp.role_account(launch["roles"]["sudo"][0]),
    "the Treasury": lambda meta, launch: lp.treasury_account(meta),
    "the dust pool": lambda meta, launch: lp.role_account(launch["roles"]["dust_pool"][0]),
    "an attestor": lambda meta, launch: lp.role_account(launch["roles"]["attestors"][0]),
}


@pytest.mark.parametrize("who", SHAPED_ACCOUNTS)
@pytest.mark.parametrize("fields", ACCOUNT_SHAPES, ids=[",".join(f"{k}={v}" for k, v in s.items())
                                                         for s in ACCOUNT_SHAPES])
def test_a_genesis_account_that_is_not_the_one_the_balances_genesis_writes_is_refused(mainnet, who, fields):
    """A sudo keyholder whose whole balance is frozen can reserve no multisig deposit, so Root can never act; a
    nonce, a consumer, a sufficient or another provider count is a state no endowment leaves."""
    spec, meta, launch = mainnet
    account = SHAPED_ACCOUNTS[who](meta, launch)
    spec.storage[account_key(account)] = account_info(spec.balance(account)[0], **fields)
    assert mainnet_supply(spec, meta, launch) == [mis_shaped(account, **fields)]


def test_dust_below_the_existential_deposit_is_refused(mainnet):
    spec, meta, launch = mainnet
    pool = launch["roles"]["dust_pool"][0]
    redust(spec, launch, "dust_pool", pool, ED - 1)
    assert mainnet_supply(spec, meta, launch) == [
        f"[4 supply] dust.dust_pool.{pool} declares 499, below the existential deposit 500: the Balances genesis "
        "endows no account less, so no build-spec writes it"]
    redust(spec, launch, "dust_pool", pool, ED)
    assert mainnet_supply(spec, meta, launch) == []


def test_reserved_dust_is_refused(mainnet):
    spec, meta, launch = mainnet
    oracle = launch["roles"]["oracle"][0]
    key = account_key(account_of(oracle))
    raw = spec.storage[key]
    spec.storage[key] = raw[:16] + (54_000).to_bytes(16, "little") + (1_000).to_bytes(16, "little") + raw[48:]
    assert mainnet_supply(spec, meta, launch) == [
        f"[4 supply] genesis endows {oracle} 54000 free and 1000 reserved, but dust.oracle.{oracle} declares 55000"]


def test_dust_genesis_does_not_hold_is_refused(mainnet):
    spec, meta, launch = mainnet
    oracle = launch["roles"]["oracle"][0]
    del spec.storage[account_key(account_of(oracle))]
    assert f"[4 supply] genesis endows {oracle} 0 free and 0 reserved, but dust.oracle.{oracle} declares 55000" \
           in mainnet_supply(spec, meta, launch)


def test_a_treasury_endowed_other_than_its_existential_deposit_is_refused(mainnet):
    spec, meta, launch = mainnet
    set_account(spec, TREASURY, ED + 1)
    assert mainnet_supply(spec, meta, launch)[0] == (
        f"[4 supply] genesis endows {ss58(TREASURY)} 501 free and 0 reserved, but the Treasury's existential deposit "
        "declares 500")


@pytest.mark.parametrize("edit, fault", [
    (lambda dust, roles: dust.update(treasurer={ss58(fresh_account()): 1}),
     "dust.treasurer endows a role roles does not declare"),
    (lambda dust, roles: dust["oracle"].update({roles["enactor"][0]: 1}),
     "dust.oracle.{enactor} names an account that is no entry of roles.oracle"),
    (lambda dust, roles: dust.update(enactor={roles["enactor"][0]: 110_000, "0x" + account_of(
        roles["enactor"][0]).hex(): 1}),
     "dust.enactor.{enactor} endows the account dust.enactor.0x{enactor_hex} endows"),
    (lambda dust, roles: dust["oracle"].update({"5Garbage": 1}),
     "dust.oracle.5Garbage: SS58 payload is not a 32-byte account; dust names an account by its public key, or a "
     "multisig by its account"),
], ids=["an undeclared role", "another role's entry", "an account twice", "not a key"])
def test_dust_that_names_no_entry_of_its_role_once_is_refused(mainnet, edit, fault):
    spec, meta, launch = mainnet
    edit(launch["dust"], launch["roles"])
    enactor = launch["roles"]["enactor"][0]
    want = "[4 supply] " + fault.format(enactor=enactor, enactor_hex=account_of(enactor).hex())
    assert want in mainnet_supply(spec, meta, launch)


def test_a_launch_that_declares_no_dust_is_refused(mainnet):
    spec, meta, launch = mainnet
    del launch["dust"]
    assert mainnet_supply(spec, meta, launch) == [
        "[4 supply] the launch declares no dust: what each genesis account holds is unchecked"]


def test_a_genesis_that_issues_a_matra_is_refused(mainnet):
    spec, meta, launch = mainnet
    pool = launch["roles"]["dust_pool"][0]
    redust(spec, launch, "dust_pool", pool, lp.MATRA - 977_000 + 90_000)
    assert mainnet_supply(spec, meta, launch) == [
        "[4 supply] genesis issues 1000000 base units, at least one MATRA (1000000): a mainnet genesis issues dust, "
        "enough for each role account to exist and sign"]


def test_the_issuance_cap_is_the_runtimes_matra():
    source = (HERE.parent.parent / "partnerchain/runtime/src/lib.rs").read_text()
    assert "pub const MATRA_DECIMALS: u32 = 6;" in source
    assert "pub const MATRA: Balance = 10u128.pow(MATRA_DECIMALS);" in source
    assert lp.MATRA == 10**6


@pytest.mark.parametrize("item", ["AttestationRewardPerSigner", "ReceiptSubmissionFee", "ReceiptSubmissionFeeFloor",
                                  "BondRequirement"])
@pytest.mark.parametrize("value", [1, None], ids=["one", "unset"])
def test_a_fixed_issuance_genesis_that_pays_or_bonds_anything_is_refused(mainnet, item, value):
    spec, meta, launch = mainnet
    key = lp.storage_key("OrinqReceipts", item)
    if value is None:
        del spec.storage[key]
    else:
        spec.storage[key] = value.to_bytes(16, "little")
    shown = "sets no" if value is None else "stores 1 as"
    assert mainnet_supply(spec, meta, launch) == [
        f"[4 supply] genesis {shown} OrinqReceipts.{item}: a genesis that fixes its issuance stores it as 0, since "
        "nothing is minted to pay it and no MATRA moves"]


def test_no_emission_reserve_counts_against_the_lock_of_a_fixed_issuance(mainnet):
    spec, meta, launch = mainnet
    assert ("OrinqReceipts", "ValidatorEmissionReserve") in meta.constants
    assert mainnet_supply(spec, meta, launch, locked(977_000, launch["supply"]["genesis_lock"]["address"])) == []


def test_a_fixed_issuance_above_the_cardano_lock_is_refused(mainnet):
    spec, meta, launch = mainnet
    assert mainnet_supply(spec, meta, launch, locked(976_999, launch["supply"]["genesis_lock"]["address"])) == [
        f"[4 supply] Materios issues 977000 at genesis against 976999 cMATRA locked on Cardano at "
        f"{launch['supply']['genesis_lock']['utxo']}: the difference is MATRA no cMATRA backs"]


@A_BYTE_OFF
@pytest.mark.parametrize("item, width", [("FixedIssuance", 16), ("AttestationThreshold", 4)])
def test_a_fixed_issuance_or_attestation_threshold_at_another_width_is_an_input_error(mainnet, item, width, change):
    spec, meta, launch = mainnet
    stored = spec.uint("OrinqReceipts", item, width)
    put(spec, "OrinqReceipts", item, stored.to_bytes(width + change, "little"))
    check = lp.check_supply if item == "FixedIssuance" else lp.check_attestation_committee
    args = (spec, meta, launch, NO_CARDANO) if item == "FixedIssuance" else (spec, meta, launch)
    with pytest.raises(lp.InputError, match="^" + re.escape(mis_sized(f"OrinqReceipts.{item}", width + change, width))):
        check(*args)


def test_an_attestation_committee_that_does_not_decode_is_an_input_error(mainnet):
    spec, meta, launch = mainnet
    put(spec, "OrinqReceipts", "CommitteeMembers", spec.value("OrinqReceipts", "CommitteeMembers") + bytes(1))
    with pytest.raises(lp.InputError, match="^OrinqReceipts.CommitteeMembers does not decode as a set of 32-byte "
                                            "accounts$"):
        lp.check_attestation_committee(spec, meta, launch)


def test_check_needs_the_operators_key_table(tmp_path, capsys):
    """26 of the 28 keys preprod's genesis names were in no public table before the exposed table, so a check run
    without the operator's table would pass the keys only that table names."""
    plain = tmp_path / "plain.json"
    plain.write_text("{}")
    with pytest.raises(SystemExit) as refused:
        lp.main(["check", "--spec", str(plain), "--launch", str(plain), "--signed-manifest", str(plain),
                 "--kupo", "http://127.0.0.1:9"])
    assert refused.value.code == 2
    assert "the following arguments are required: --extra-well-known" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Rule 12: every signer's dust floor
# ---------------------------------------------------------------------------

def dust_findings(spec, meta, launch) -> list[str]:
    return messages(lp.check_dust(spec, meta, launch))


# The genesis runtime code the dust tests size an upgrade by: 900,000 bytes, of which its length alone is read. The
# call that carries an upgrade is sized at twice that.
RUNTIME_BYTES = 900_000
UPGRADE_BYTES = 2 * RUNTIME_BYTES
BLOCKS_A_DAY = 14_400


@pytest.fixture
def sized(mainnet):
    """The mainnet fixture with a genesis runtime code of RUNTIME_BYTES."""
    spec, meta, launch = mainnet
    spec.storage[lp.CODE_KEY] = bytes(RUNTIME_BYTES)
    return spec, meta, launch


def lowest_motra(free: int, loads, days: int = 8) -> float:
    """The lowest MOTRA balance an account that holds `free` MATRA base units reaches over `days` of `loads`, each
    (calls a day, bytes of one) with its calls evenly spaced from the first block, starting from the balance it
    settles at: block by block as the runtime's MOTRA pallet moves it under mainnet's parameters, keeping 99.99% of
    the balance, adding 10^4 a base unit, then paying 10^9 + 10^6 a byte for each call that is due."""
    generated = free * 10**4
    balance = lowest = generated / 1e-4
    due = [0.0] * len(loads)
    for block in range(days * BLOCKS_A_DAY):
        balance = balance * 0.9999 + generated
        for i, (calls, length) in enumerate(loads):
            while due[i] <= block:
                balance -= 1e9 + 1e6 * length
                due[i] += BLOCKS_A_DAY / calls
        lowest = min(lowest, balance)
    return lowest


# What a key that signs for each role signs in a day, (calls, bytes of one), and whether it also signs an upgrade.
LOADS = {"sudo": ((24, 512), True), "guardian": ((64, 384), False), "enactor": ((64, 512), True),
         "anchor_signer": ((2_000, 256), False), "gateway_sponsor": ((6_000, 560), False),
         "oracle": ((4_800, 512), False), "attestors": ((400, 4_288), False), "recovery_friends": ((8, 256), False),
         "recovery_rescuers": ((24, 512), False)}
# What a key that signs for a role pays for together starting from no MOTRA, (calls, blocks), as the launch decided
# it: a guardian's veto within ten blocks, 500 sponsored receipts after two hours, a friend's vouch within sixty
# blocks and a rescuer's call every thirty.
BURSTS = {"guardian": (1, 10), "gateway_sponsor": (500, 1_200), "recovery_friends": (1, 60),
          "recovery_rescuers": (1, 30)}
SIMULATED = [([load], upgrades) for load, upgrades in LOADS.values()] + [
    ([LOADS["sudo"][0], LOADS["oracle"][0]], True),
    ([LOADS["attestors"][0], LOADS["recovery_friends"][0], LOADS["guardian"][0]], False)]


# The head of the table docs/MAINNET-GENESIS.md gives each role's load, burst and builder's floor in.
FLOOR_TABLE = "| Role account | Load sized for | Answers from no MOTRA | Floor (base units) |"


def test_the_preflight_sizes_each_role_for_the_load_the_genesis_doc_tables():
    doc = (HERE.parent.parent / "docs" / "MAINNET-GENESIS.md").read_text()
    table = doc[doc.index(FLOOR_TABLE):doc.index("## Refusals")]
    rows = {cells[0]: cells[1:3] for cells in ([cell.strip() for cell in line.strip("|").split("|")]
                                               for line in table.splitlines()[2:] if line.startswith("|"))}
    named = {"sudo": "sudo keyholder", "guardian": "guardian keyholder", "enactor": "enactor",
             "anchor_signer": "anchor_signer", "gateway_sponsor": "gateway_sponsor", "oracle": "oracle",
             "attestors": "attestor", "recovery_friends": "recovery friend", "recovery_rescuers": "recovery rescuer"}
    tabled, answered = {}, {}
    for role, name in named.items():
        calls, length = (int(number.replace(",", ""))
                         for number in re.match(r"([\d,]+) \w+ of ([\d,]+) B", rows[name][0]).groups())
        tabled[role] = ((calls, length), "and an upgrade" in rows[name][0])
        burst = re.fullmatch(r"([\d,]+) within ([\d,]+) blocks", rows[name][1])
        if burst:
            answered[role] = tuple(int(number.replace(",", "")) for number in burst.groups())
    assert tabled == LOADS and answered == BURSTS
    assert lp.ROLE_LOADS == {role: load for role, (load, _) in LOADS.items()}
    assert lp.ROLE_BURSTS == BURSTS
    assert set(lp.UPGRADE_ROLES) == {role for role, (_, upgrades) in LOADS.items() if upgrades}
    assert lp.UPGRADE_HEADROOM == 2


@pytest.mark.parametrize("loads, upgrades", SIMULATED, ids=[*LOADS, "sudo and oracle", "three roles"])
def test_working_dust_is_what_keeps_a_signers_motra_above_its_calls_block_by_block(loads, upgrades):
    """The preflight's closed form against the pallet's rule run block by block: at its working dust an account's
    MOTRA never runs out under its calls, nor falls below the fee of an upgrade where it signs one, and two percent
    less dust does."""
    upgrade_fee = 1e9 + 1e6 * UPGRADE_BYTES if upgrades else 0
    working = lp.working_dust(loads, UPGRADE_BYTES if upgrades else None, BLOCKS_A_DAY)
    assert lowest_motra(working, loads) >= upgrade_fee
    assert lowest_motra(working * 98 // 100, loads) < upgrade_fee


def motra_from_empty(free: int, blocks: int) -> float:
    """The MOTRA an account that holds `free` MATRA base units has `blocks` blocks after its balance was empty, block
    by block as the runtime's MOTRA pallet moves it under mainnet's parameters."""
    balance = 0.0
    for _ in range(blocks):
        balance = balance * 0.9999 + free * 10**4
    return balance


@pytest.mark.parametrize("role", BURSTS)
def test_burst_dust_is_what_pays_for_a_roles_burst_that_many_blocks_after_an_empty_balance(role):
    """The preflight's closed form against the pallet's rule run block by block: at its burst dust an account that
    starts with no MOTRA holds the fees of its role's burst when its blocks have passed, and one percent less dust
    does not. A block earlier it holds less than they cost, but for the 500 receipts, which a block more or less
    in 1,200 does not decide."""
    (calls, blocks), length = BURSTS[role], LOADS[role][0][1]
    fees = calls * (1e9 + 1e6 * length)
    dust = lp.burst_dust(calls, length, blocks)
    assert motra_from_empty(dust, blocks) >= fees > motra_from_empty(dust * 99 // 100, blocks)
    assert blocks > 100 or motra_from_empty(dust, blocks - 1) < fees
    assert dust == {"guardian": 13_847, "gateway_sponsor": 68_975, "recovery_friends": 2_100,
                    "recovery_rescuers": 5_048}[role]


def test_the_decay_the_burst_dust_is_worked_from_is_the_pallets():
    """pallet_motra accrues an interval in one step: the generation of each block, kept at the decay rate for the
    blocks after it, less half a base unit a block for the rounding of the block-by-block rule it replaced."""
    source = (HERE.parent.parent / "partnerchain" / "pallets" / "motra" / "src" / "decay.rs").read_text()
    assert "let sum_lower = (SCALE - upper) * BILLION / loss;" in source
    assert "let generated = mul_div(per_block, sum_lower, SCALE, Rounding::Down);" in source
    assert "let rounding_loss = sum_upper.saturating_sub(SCALE).div_ceil(2 * SCALE);" in source
    assert "(decayed, generated.saturating_sub(rounding_loss))" in source


def test_the_fee_the_dust_is_sized_for_is_the_runtimes_below_its_congestion_target():
    """pallet_motra's compute_fee: the minimum fee, the congestion rate's price of the weight, which is nothing at
    the zero rate genesis starts at, and the price of the bytes."""
    source = (HERE.parent.parent / "partnerchain" / "pallets" / "motra" / "src" / "lib.rs").read_text()
    fee = source[source.index("pub fn compute_fee("):source.index("fn normal_budget()")]
    assert "params.length_fee_per_byte.saturating_mul(len as u128)" in fee
    assert re.search(r"\.min_fee\s+\.saturating_add\(weight_component\)\s+\.saturating_add\(length_fee\)", fee)
    assert [lp.motra_fee(0), lp.motra_fee(512)] == [10**9, 10**9 + 512 * 10**6]


# Each signer of the fixture with the deposits the runtime's constants reserve from it and the working dust its
# role's calls take, worked here apart from the preflight. The deposits: a 2-of-3 keyholder's multisig deposit,
# DepositBase 1,000 + DepositFactor 500 x 2; the sudo account's recovery configuration of its 3 friends and one
# more, ConfigDepositBase 1,000 + FriendDepositFactor 500 x 4; a rescuer's RecoveryDeposit 1,000. The working dust
# settles at 10^8 MOTRA a base unit, and has to cover each role's fee f over 1 - 0.9999^k for a call every k blocks:
# 24 calls of 512 bytes a day take 260, 64 of 384 take 623, 64 of 512 take 680, 2,000 of 256 take 17,453, 6,000 of
# 560 take 65,015, 4,800 of 512 take 50,413, 400 of 4,288 take 14,717 and 8 of 256 take 77; a 1,800,000-byte upgrade
# takes 18,010 more. A burst takes its fees over what a base unit generates in its blocks from an empty balance: a veto of
# 384 bytes within 10 blocks takes 13,847, 500 receipts of 560 within 1,200 take 68,975, a vouch of 256 within 60
# takes 2,100 and a rescuer's call of 512 within 30 takes 5,048, each more than its role's calls a day take. The
# floor is the deposits and, left free, the larger of the existential deposit 500 and the working dust.
SIGNER_FLOORS = [
    (("roles", "sudo", 0, "members", 1), "roles.sudo[0].members[1], a keyholder of roles.sudo[0]", 2_000, 18_270),
    (("roles", "guardian", 0, "members", 1), "roles.guardian[0].members[1], a keyholder of roles.guardian[0]", 2_000,
     13_847),
    (("roles", "sudo", 0), "roles.sudo[0], which reserves a recovery configuration of up to 4 friends", 3_000, 0),
    (("roles", "recovery_rescuers", 0), "roles.recovery_rescuers[0]", 1_000, 5_048),
    (("roles", "enactor", 0), "roles.enactor[0]", 0, 18_690),
    (("roles", "anchor_signer", 1), "roles.anchor_signer[1]", 0, 17_453),
    (("roles", "oracle", 2), "roles.oracle[2]", 0, 50_413),
    (("roles", "gateway_sponsor", 1), "roles.gateway_sponsor[1]", 0, 68_975),
    (("roles", "attestors", 1), "roles.attestors[1]", 0, 14_717),
    (("roles", "recovery_friends", 0), "roles.recovery_friends[0]", 0, 2_100),
]


def signer(launch: dict, path: tuple) -> bytes:
    entry = launch
    for step in path:
        entry = entry[step]
    return lp.role_account(entry)


def below_floor(who: str, account: bytes, held: int, reserved: int, working: int, upgrades: bool) -> str:
    upgrade = f", a {UPGRADE_BYTES}-byte runtime upgrade among them" if upgrades else ""
    return (f"[12 dust] {who} ({ss58(account)}) holds {held} free at genesis, below its floor of "
            f"{reserved + max(ED, working)}: the {reserved} its roles reserve and, left free, the larger of the "
            f"existential deposit 500 and the working dust {working} that generates the MOTRA its calls cost{upgrade}")


@pytest.mark.parametrize("path, who, reserved, working", SIGNER_FLOORS, ids=[who for _, who, _, _ in SIGNER_FLOORS])
def test_a_signer_at_its_dust_floor_passes_and_one_unit_below_is_refused(sized, path, who, reserved, working):
    spec, meta, launch = sized
    account, floor = signer(launch, path), reserved + max(ED, working)
    set_account(spec, account, floor)
    assert dust_findings(spec, meta, launch) == []
    set_account(spec, account, floor - 1)
    upgrades = path[1] == "enactor" or path[1:] == ("sudo", 0, "members", 1)
    assert dust_findings(spec, meta, launch) == [below_floor(who, account, floor - 1, reserved, working, upgrades)]


def test_a_keyholder_left_only_the_existential_deposit_once_its_deposit_is_reserved_is_refused(sized):
    """The floor before working dust: the existential deposit and the multisig deposit, which leaves a sudo keyholder
    500 base units free once it opens a call, settling at 5 x 10^10 MOTRA where the upgrade it signs costs 1.8 x
    10^12."""
    spec, meta, launch = sized
    account = signer(launch, ("roles", "sudo", 0, "members", 0))
    set_account(spec, account, 2_500)
    assert dust_findings(spec, meta, launch) == [
        below_floor("roles.sudo[0].members[0], a keyholder of roles.sudo[0]", account, 2_500, 2_000, 18_270, True)]


def test_a_longer_genesis_runtime_raises_the_floor_of_those_who_sign_an_upgrade(sized):
    spec, meta, launch = sized
    assert dust_findings(spec, meta, launch) == []
    spec.storage[lp.CODE_KEY] = bytes(6_000_000)
    found = dust_findings(spec, meta, launch)
    assert len(found) == 4 and all("a 12000000-byte runtime upgrade among them" in message for message in found)
    assert [message.split(" (")[0] for message in found] == [
        f"[12 dust] roles.sudo[0].members[{i}], a keyholder of roles.sudo[0]" for i in range(3)] + [
        "[12 dust] roles.enactor[0]"]


def documented_floors() -> dict[str, int]:
    """The floor the node's builder holds each role account to, as docs/MAINNET-GENESIS.md tables them."""
    doc = (HERE.parent.parent / "docs" / "MAINNET-GENESIS.md").read_text()
    table = doc[doc.index(FLOOR_TABLE):doc.index("## Refusals")]
    rows = [[cell.strip() for cell in line.strip("|").split("|")] for line in table.splitlines()[2:]
            if line.startswith("|")]
    return {row[0]: int(row[3].replace(",", "")) for row in rows}


def test_the_builders_floor_of_each_role_covers_the_preflights_whatever_runtime_a_block_holds(mainnet):
    """The node's builder sizes an upgrade at a block-long call, 5 MiB, and adds its working dust to the existential
    deposit; the preflight sizes it at twice the genesis runtime and counts the existential deposit as free dust
    that generates. The builder works a burst from the pallet's rule a block at a time, each block rounded down, and
    the preflight from its closed form. So an account at the builder's floor passes rule 12 even where the genesis
    runtime is as long as a block."""
    spec, meta, launch = mainnet
    floors = documented_floors()
    assert floors == {"sudo keyholder": 107_630, "guardian keyholder": 16_347, "enactor": 106_050,
                      "anchor_signer": 17_945, "gateway_sponsor": 69_478, "oracle": 50_900, "attestor": 15_189,
                      "recovery friend": 2_600, "recovery rescuer": 6_548, "sudo account": 3_500}
    assert meta.constants[("System", "BlockLength")][4:8] == (5 * 1024 * 1024).to_bytes(4, "little")
    spec.storage[lp.CODE_KEY] = bytes(5 * 1024 * 1024)
    roles = launch["roles"]
    held = {"sudo keyholder": roles["sudo"][0]["members"], "guardian keyholder": roles["guardian"][0]["members"],
            "enactor": roles["enactor"], "anchor_signer": roles["anchor_signer"],
            "gateway_sponsor": roles["gateway_sponsor"], "oracle": roles["oracle"], "attestor": roles["attestors"],
            "recovery friend": roles["recovery_friends"], "recovery rescuer": roles["recovery_rescuers"],
            "sudo account": roles["sudo"]}
    for name, entries in held.items():
        for entry in entries:
            set_account(spec, lp.role_account(entry), floors[name])
    assert dust_findings(spec, meta, launch) == []


def test_a_signer_with_no_provider_is_refused(mainnet):
    spec, meta, launch = mainnet
    enactor, anchor = signer(launch, ("roles", "enactor", 0)), signer(launch, ("roles", "anchor_signer", 0))
    set_account(spec, enactor, 120_000, providers=0)
    del spec.storage[account_key(anchor)]
    assert dust_findings(spec, meta, launch) == [
        f"[12 dust] roles.anchor_signer[0] ({ss58(anchor)}) has no provider at genesis: it cannot sign, and nothing "
        "after genesis endows it",
        f"[12 dust] roles.enactor[0] ({ss58(enactor)}) has no provider at genesis: it cannot sign, and nothing after "
        "genesis endows it"]


def test_a_keyholder_of_two_multisigs_needs_both_deposits_and_carries_both_roles_calls(sized):
    spec, meta, launch = sized
    oracle = launch["roles"]["oracle"][0]
    member = launch["roles"]["sudo"][0]["members"][0]["key"]
    launch["roles"]["oracle"][0] = msig(2, account_of(member), fresh_account())
    account = account_of(member)
    set_account(spec, account, 72_682)
    assert below_floor("roles.sudo[0].members[0], a keyholder of roles.sudo[0] and roles.oracle[0].members[0], a "
                       "keyholder of roles.oracle[0]", account, 72_682, 4_000, 68_683, True) \
        in dust_findings(spec, meta, launch)
    set_account(spec, account, 72_683)
    assert not any(ss58(account) in message for message in dust_findings(spec, meta, launch))
    assert oracle not in json.dumps(launch["roles"]["oracle"])


def test_a_guardian_keyholder_that_is_also_an_oracle_needs_both_roles_calls_and_the_veto_on_top(sized):
    """64 vetoes of 384 bytes and 4,800 prices of 512 a day take 51,035 to sustain, and the veto within ten blocks
    13,847 more, since the prices spend what the veto was saved from: 2,000 reserved and 64,882 free."""
    spec, meta, launch = sized
    member = launch["roles"]["guardian"][0]["members"][1]["key"]
    launch["roles"]["oracle"][0] = member
    account = account_of(member)
    who = "roles.guardian[0].members[1], a keyholder of roles.guardian[0] and roles.oracle[0]"
    set_account(spec, account, 66_881)
    assert below_floor(who, account, 66_881, 2_000, 64_882, False) in dust_findings(spec, meta, launch)
    set_account(spec, account, 66_882)
    assert not any(ss58(account) in message for message in dust_findings(spec, meta, launch))


def test_a_sponsors_keyholder_that_is_also_an_attestor_needs_both_roles_calls_and_the_burst_on_top(sized):
    """400 evidence submissions of 4,288 bytes and 6,000 receipts of 560 a day take 79,732 to sustain, and the 500
    receipts after two hours 68,975 more: 2,000 reserved and 148,707 free."""
    spec, meta, launch = sized
    attestor = launch["roles"]["attestors"][0]
    other = fresh_account()
    launch["roles"]["gateway_sponsor"][0] = msig(2, account_of(attestor), other)
    account = account_of(attestor)
    set_account(spec, other, 200_000)
    who = "roles.attestors[0] and roles.gateway_sponsor[0].members[0], a keyholder of roles.gateway_sponsor[0]"
    set_account(spec, account, 150_706)
    assert below_floor(who, account, 150_706, 2_000, 148_707, False) in dust_findings(spec, meta, launch)
    set_account(spec, account, 150_707)
    assert not any(ss58(account) in message for message in dust_findings(spec, meta, launch))


def test_a_dust_pool_account_that_also_holds_a_key_is_refused(sized):
    """The floor of a keyholder listed in the dust pool is not spare dust for later signers."""
    spec, meta, launch = sized
    member = launch["roles"]["sudo"][0]["members"][0]["key"]
    launch["roles"]["dust_pool"] = [member]
    set_account(spec, account_of(member), 200_000)
    assert dust_findings(spec, meta, launch) == [
        f"[12 dust] roles.dust_pool[0] ({ss58(account_of(member))}) is also roles.sudo[0].members[0], a keyholder of "
        "roles.sudo[0]: the dust pool holds dust for signers admitted after genesis, and none of the dust an account "
        "needs for a role of its own is spare"]


def test_a_dust_pool_below_the_later_signers_the_launch_declares_is_refused(sized):
    """A later signer of 2,000 receipts of 560 bytes a day takes 21,677: four take 86,708 over the pool's accounts."""
    spec, meta, launch = sized
    assert launch["later_signers"] == 4
    pool = account_of(launch["roles"]["dust_pool"][0])
    set_account(spec, pool, 86_708)
    assert dust_findings(spec, meta, launch) == []
    set_account(spec, pool, 86_707)
    assert dust_findings(spec, meta, launch) == [
        "[12 dust] the dust pool holds 86707 free at genesis, below the 86708 that later_signers = 4 take at 21677 "
        "each, the working dust of 2000 calls of 560 bytes a day"]
    launch["later_signers"] = 5
    set_account(spec, pool, 86_708)
    assert dust_findings(spec, meta, launch) == [
        "[12 dust] the dust pool holds 86708 free at genesis, below the 108385 that later_signers = 5 take at 21677 "
        "each, the working dust of 2000 calls of 560 bytes a day"]


@pytest.mark.parametrize("pallet, constant", [("Balances", "ExistentialDeposit"), ("Multisig", "DepositFactor"),
                                              ("Recovery", "RecoveryDeposit"), ("Recovery", "MaxFriends")])
def test_a_runtime_that_hides_a_deposit_is_refused(mainnet, pallet, constant):
    spec, meta, launch = mainnet
    del meta.constants[(pallet, constant)]
    assert dust_findings(spec, meta, launch) == [
        f"[12 dust] the runtime metadata declares no {pallet}.{constant} the preflight can read: the dust each signer "
        "needs is unknown here"]


@pytest.mark.parametrize("hidden", [None, bytes(8)], ids=["undeclared", "zero"])
def test_a_runtime_that_hides_how_long_a_block_lasts_is_refused(mainnet, hidden):
    """A day's blocks, by the runtime's slot duration, are what a role's calls a day are spaced over."""
    spec, meta, launch = mainnet
    assert lp.uint_constant(meta, "Aura", "SlotDuration", 8) == 6_000
    if hidden is None:
        del meta.constants[("Aura", "SlotDuration")]
    else:
        meta.constants[("Aura", "SlotDuration")] = hidden
    assert dust_findings(spec, meta, launch) == [
        "[12 dust] the runtime metadata declares no Aura.SlotDuration above 0 the preflight can read: the dust each "
        "signer needs is unknown here"]


# ---------------------------------------------------------------------------
# Rule 9: partner-chain keys, the genesis UTXO and its scripts, the age of the committee datums
# ---------------------------------------------------------------------------

def test_genesis_grandpa_voters_past_the_runtimes_bound_are_refused(mainnet):
    spec, meta, launch = mainnet
    meta.constants[("Grandpa", "MaxAuthorities")] = (3).to_bytes(4, "little")
    assert committee_findings(spec, meta, launch) == [
        "[9 committee] genesis Grandpa.Authorities lists 4 voters, more than the runtime's Grandpa.MaxAuthorities 3: "
        "the runtime cannot decode it and reads no voter, and GRANDPA refuses an empty authority set"]
    del meta.constants[("Grandpa", "MaxAuthorities")]
    assert committee_findings(spec, meta, launch) == [
        "[9 committee] the runtime metadata declares no Grandpa.MaxAuthorities the preflight can read: whether the "
        "runtime can decode the genesis voters is unknown here"]


def test_the_runtime_bounds_its_aura_and_grandpa_authorities_at_its_committee_bound(mainnet):
    """Aura's bound is in no metadata: the runtime sets it, and GRANDPA's, to the MaxValidators that rule 9 holds
    the genesis committee, and so both lists, within."""
    _, meta, _ = mainnet
    source = (HERE.parent.parent / "partnerchain" / "runtime" / "src" / "lib.rs").read_text()
    assert source.count("    type MaxAuthorities = MaxValidators;\n") == 2
    assert ("Aura", "MaxAuthorities") not in meta.constants
    assert lp.uint_constant(meta, "Grandpa", "MaxAuthorities", 4) \
        == lp.uint_constant(meta, "SessionCommitteeManagement", "MaxValidators", 4) == 32


def test_a_genesis_committee_member_under_another_partner_chain_key_is_refused(mainnet):
    spec, meta, launch = mainnet
    _, members = lp.genesis_committee(spec)
    node = next(node for node in launch["nodes"] if bytes.fromhex(node["aura"][2:]) == members[1][1])
    node["cross_chain"] = "0x" + fresh_ecdsa_key().hex()
    assert committee_findings(spec, meta, launch) == [
        f"[9 committee] genesis SessionCommitteeManagement.CurrentCommittee[1] cross-chain key 0x{members[1][0].hex()} "
        f"is not the cross_chain key authority {node['name']} declares: genesis seats it under a partner-chain key no "
        "declared authority holds, and files its session keys under that key's account"]


def fixture_candidates(launch: dict) -> list[lp.Candidate]:
    return [lp.Candidate(bytes.fromhex(node["cross_chain"][2:]), bytes.fromhex(node["aura"][2:]),
                         bytes.fromhex(node["grandpa"][2:])) for node in launch["nodes"] if node["authority"]]


def test_cardano_candidates_under_their_authorities_partner_chain_keys_pass(mainnet):
    _, _, launch = mainnet
    cardano = lp.CardanoView(lock=None, candidates=fixture_candidates(launch), d_parameter=(4, 0))
    assert messages(lp.check_candidate_authorities(launch, cardano)) == []


def test_a_cardano_candidate_under_another_partner_chain_key_is_refused(mainnet):
    _, _, launch = mainnet
    candidates = fixture_candidates(launch)
    other = fresh_ecdsa_key()
    candidates[2] = dataclasses.replace(candidates[2], partner_chains_key=other)
    cardano = lp.CardanoView(lock=None, candidates=candidates, d_parameter=(4, 0))
    assert messages(lp.check_candidate_authorities(launch, cardano)) == [
        f"[9 committee] Cardano permissioned candidate 2 partner chains key 0x{other.hex()} is not the cross_chain key "
        f"authority {launch['nodes'][2]['name']} declares with its aura key: once the committee is drawn from Cardano "
        "it seats that authority under a partner-chain key no declared authority holds"]


PREPROD_GENESIS_UTXO = "13313ea0119e0c4330f64f1809159064a371a1bbf2050b1fe13d5492280dca50#0"


# The vectors partner-chains v1.8.0's get-scripts gives, which the setup kit's derivation and the builder's
# committee_candidate.rs pin: preprod's genesis UTXO derives the scripts preprod's genesis stores, and the mainnet
# fixture's the values its manifest names.
@pytest.mark.parametrize("utxo, committee, d_parameter, candidates", [
    (PREPROD_GENESIS_UTXO, "fed2f2fdc87b0a9d6e91220cb2788107793413b094e172a414b0a05c",
     "38dddaf5198b927b19dac9b28226ab29eddad176d5d81c7748bc2c31",
     "ef2890d1e98247819abcf2df6e891824ed950a4216d36c71ee6f9974"),
    (f"{PARTNER_CHAIN_UTXO}#0", "89b87902e4f8ac97c257e9fbde79dfabbf97cecb4116f30b9b135171",
     "bca168784c7086baa491ff876a1e9d6ee2b8a418a841dc0d445a674e",
     "8d5698c66e509f7758befcca95b5bc1632daf4b864d5fdd049dc40b2"),
], ids=["preprod", "the mainnet fixture"])
def test_the_scripts_a_genesis_utxo_derives_are_partner_chains(utxo, committee, d_parameter, candidates):
    assert [value.hex() for value in lp.partner_chain_scripts(utxo)] == [committee, d_parameter, candidates]


def test_preprods_genesis_stores_the_scripts_its_genesis_utxo_derives(spec244):
    spec, _ = spec244
    tx, index = PREPROD_GENESIS_UTXO.split("#")
    assert spec.value("Sidechain", "GenesisUtxo") == bytes.fromhex(tx) + int(index).to_bytes(2, "little")
    validator, d_policy, candidates_policy = lp.partner_chain_scripts(PREPROD_GENESIS_UTXO)
    address, stored_d, stored_candidates = lp.main_chain_scripts(spec)
    assert lp.bech32_decode(address) == ("addr_test", bytes([0x70]) + validator)
    assert (stored_d, stored_candidates) == (d_policy, candidates_policy)


def test_the_mainnet_fixture_names_the_committee_candidate_address_its_genesis_utxo_derives(mainnet):
    _, _, launch = mainnet
    validator, _, _ = lp.partner_chain_scripts(launch["partner_chain"]["genesis_utxo"])
    assert lp.committee_candidate_address(validator) == launch["partner_chain"]["committee_candidate_address"] \
        == "addr1wxyms7gzunu2e97z2l5lhhnem74ml97wedq3ductnvf4zug6kx8rr"


def test_each_genesis_utxo_derives_scripts_of_its_own():
    tx, _ = PREPROD_GENESIS_UTXO.split("#")
    other = tx[:-1] + ("1" if tx[-1] != "1" else "2")
    derived = [lp.partner_chain_scripts(utxo) for utxo in
               (f"{tx}#0", f"{tx}#1", f"{tx}#300", f"{tx}#32767", f"{other}#0")]
    assert len({script for scripts in derived for script in scripts}) == 3 * len(derived)


def test_the_vendored_committee_candidate_validator_is_the_one_the_builder_applies():
    source = (HERE.parent.parent / "partnerchain/node/src/chain_spec_mainnet/committee_candidate.rs").read_text()
    builder = "".join(re.findall(r'"([0-9a-f]+)"', source[source.index("COMMITTEE_CANDIDATE_VALIDATOR"):
                                                          source.index(");", source.index("hex!("))]))
    assert lp.partner_chains_scripts()["committee_candidate_validator"].hex() == builder


def test_the_utxo_is_the_plutus_data_partner_chains_writes():
    """Constr 0 [Constr 0 [tx hash], index], each non-empty list of fields of indefinite length."""
    tx = "ab" * 32
    data = lp._data_constr(0, [lp._data_constr(0, [lp._data_bytes(bytes.fromhex(tx))]), lp._cbor_head(0, 300)])
    assert data.hex() == f"d8799fd8799f5820{tx}ff19012cff"
    assert lp._script_address_data(bytes(28)).hex() == "d8799fd87a9f581c" + "00" * 28 + "ffd87a80ff"


@pytest.mark.parametrize("script", [
    lambda raw: raw + b"\0", lambda raw: raw[:1] + bytes([raw[1] + 1]) + raw[2:] + b"\0", lambda raw: raw[1:],
    lambda raw: b""], ids=["a byte after it", "a longer length", "no CBOR head", "empty"])
def test_a_script_that_is_not_one_whole_cbor_byte_string_is_not_applied(script):
    with pytest.raises(ValueError):
        lp.apply_data(script(lp.partner_chains_scripts()["committee_candidate_validator"]), b"\0")


def partner_chain_findings(spec, launch) -> list[str]:
    return messages(lp.check_partner_chain(spec, launch))


def derives(name: str, given: str, want: str) -> str:
    return (f"[9 committee] {name} is {given}, not {want}, which {PARTNER_CHAIN_UTXO}#0 derives: the committee is "
            "drawn through scripts the partner chain's setup did not make")


GENESIS_SCRIPTS = "genesis SessionCommitteeManagement.MainChainScriptsConfiguration"


@pytest.mark.parametrize("field, index", [("d_parameter_policy_id", 1), ("permissioned_candidates_policy_id", 2)])
def test_a_committee_policy_other_than_the_genesis_utxo_derives_is_refused(mainnet, field, index):
    spec, _, launch = mainnet
    want = launch["partner_chain"][field]
    other = "0x" + os.urandom(28).hex()
    launch["partner_chain"][field] = other
    raw = spec.value("SessionCommitteeManagement", "MainChainScriptsConfiguration")
    start = len(raw) - 28 * (3 - index)
    put(spec, "SessionCommitteeManagement", "MainChainScriptsConfiguration",
        raw[:start] + bytes.fromhex(other[2:]) + raw[start + 28:])
    assert partner_chain_findings(spec, launch) == [derives(f"partner_chain.{field}", other, want),
                                                    derives(f"{GENESIS_SCRIPTS} {field}", other, want)]


def test_a_committee_candidate_address_other_than_the_genesis_utxo_derives_is_refused(mainnet):
    spec, _, launch = mainnet
    want = launch["partner_chain"]["committee_candidate_address"]
    other = lp.committee_candidate_address(os.urandom(28))
    launch["partner_chain"]["committee_candidate_address"] = other
    _, d_policy, candidates_policy = lp.main_chain_scripts(spec)
    put(spec, "SessionCommitteeManagement", "MainChainScriptsConfiguration",
        lp.compact(len(other)) + other.encode() + d_policy + candidates_policy)
    assert partner_chain_findings(spec, launch) == [
        derives("partner_chain.committee_candidate_address", other, want),
        derives(f"{GENESIS_SCRIPTS} committee_candidate_address", other, want)]


def test_a_genesis_utxo_other_than_the_declared_one_is_refused(mainnet):
    spec, _, launch = mainnet
    put(spec, "Sidechain", "GenesisUtxo", bytes.fromhex(PARTNER_CHAIN_UTXO) + (1).to_bytes(2, "little"))
    assert partner_chain_findings(spec, launch) == [
        f"[9 committee] genesis Sidechain.GenesisUtxo is 0x{PARTNER_CHAIN_UTXO}0100, not partner_chain.genesis_utxo "
        f"{PARTNER_CHAIN_UTXO}#0: the chain is another partner chain than the one set up"]


def test_a_launch_that_declares_another_genesis_utxo_than_its_scripts_is_refused(mainnet):
    """The manifest moved to another genesis UTXO, the genesis built from the old one: every value differs."""
    spec, _, launch = mainnet
    launch["partner_chain"]["genesis_utxo"] = PREPROD_GENESIS_UTXO
    found = partner_chain_findings(spec, launch)
    assert found[0].startswith("[9 committee] genesis Sidechain.GenesisUtxo is 0x09b6fee1")
    assert len(found) == 7 and all(f"which {PREPROD_GENESIS_UTXO} derives" in message for message in found[1:])


def test_a_launch_that_declares_no_partner_chain_is_refused(mainnet):
    spec, _, launch = mainnet
    del launch["partner_chain"]
    assert partner_chain_findings(spec, launch) == [
        "[9 committee] the launch declares no partner_chain: the genesis UTXO and the Cardano scripts the committee is "
        "drawn through are unchecked"]


# Cardano mainnet's Shelley layout: epoch 208 starts at slot 4,492,800, 2020-07-29T21:44:51Z, and an epoch is 432,000
# one-second slots.
def epoch_slot(epoch: int, into: int = 0) -> int:
    return 4_492_800 + (epoch - 208) * 432_000 + into


def test_the_cardano_epoch_of_a_slot_is_mainnets():
    assert [lp.cardano_epoch(slot) for slot in (4_492_800, 4_924_799, 4_924_800)] == [208, 208, 209]
    assert lp.cardano_epoch_start(208) == "2020-07-29T21:44:51Z"
    assert lp.cardano_epoch_start(600) == "2025-12-10T21:44:51Z"


def test_a_slot_before_the_shelley_era_is_an_input_error():
    with pytest.raises(lp.InputError, match="^Cardano slot 4492799 is before Cardano mainnet's Shelley era"):
        lp.cardano_epoch(4_492_799)


def aged(now: int, d_parameter: int, candidates: int) -> lp.CardanoView:
    return lp.CardanoView(lock=None, candidates=[], d_parameter=(0, 0), tip_slot=epoch_slot(now, 431_999),
                          created={"D-parameter": epoch_slot(d_parameter, 5),
                                   "permissioned candidates": epoch_slot(candidates)})


# A mainnet session: 600 slots of 6 seconds, an hour, which starts on the hour.
SESSION_MILLIS = 3_600_000


def too_young(what: str, created: int, now: int) -> str:
    return (f"[9 committee] the {what} output was created in Cardano epoch {created}, and a launch in epoch {now} "
            f"reads the committee from epoch {now - 2}, when it did not exist: the node's follower finds no {what} "
            f"and no block is authored. The earliest valid launch is in the first session that starts in epoch "
            f"{created + 2}, from {lp.cardano_epoch_start(created + 2, SESSION_MILLIS)}")


def age_findings(mainnet, cardano: lp.CardanoView) -> list[str]:
    spec, meta, _ = mainnet
    return messages(lp.check_committee_age(spec, meta, cardano))


def test_committee_datums_two_epochs_old_pass(mainnet):
    assert age_findings(mainnet, aged(600, 598, 500)) == []


@pytest.mark.parametrize("d_parameter, candidates", [(599, 598), (598, 600), (600, 599)])
def test_a_committee_datum_created_within_two_epochs_of_the_launch_is_refused(mainnet, d_parameter, candidates):
    assert age_findings(mainnet, aged(600, d_parameter, candidates)) == [
        too_young(what, created, 600) for what, created in
        (("D-parameter", d_parameter), ("permissioned candidates", candidates)) if created > 598]


def test_the_earliest_valid_launch_is_named_with_the_start_of_its_first_session():
    assert lp.cardano_epoch_start(601) == "2025-12-15T21:44:51Z"
    assert too_young("D-parameter", 599, 600).endswith("The earliest valid launch is in the first session that starts "
                                                       "in epoch 601, from 2025-12-15T22:00:00Z")


# A Cardano mainnet epoch starts at 21:44:51 UTC and a session on the hour, so the session that holds the first 909
# seconds of an epoch started in the epoch before, and block 1 asks for that epoch's committee.
@pytest.mark.parametrize("into, launch_epoch", [(0, 599), (60, 599), (908, 599), (909, 600), (431_999, 600)])
def test_the_launch_epoch_is_the_one_the_session_that_holds_the_tip_started_in(mainnet, into, launch_epoch):
    view = dataclasses.replace(aged(600, 598, 598), tip_slot=epoch_slot(600, into))
    assert (SHELLEY_START + epoch_slot(600) - 4_492_800) % 3_600 == 44 * 60 + 51
    assert age_findings(mainnet, view) == [too_young(what, 598, launch_epoch)
                                           for what in ("D-parameter", "permissioned candidates")
                                           if launch_epoch == 599]
    assert age_findings(mainnet, dataclasses.replace(aged(600, 597, 597), tip_slot=epoch_slot(600, into))) == []


def test_the_launch_epoch_follows_the_session_length_genesis_stores(mainnet):
    """A session of 100 slots, ten minutes, that holds the tip a minute into an epoch started 4 minutes 51 seconds
    before the epoch did."""
    spec, _, _ = mainnet
    view = dataclasses.replace(aged(600, 598, 598), tip_slot=epoch_slot(600, 60))
    put(spec, "Sidechain", "SlotsPerEpoch", (100).to_bytes(4, "little"))
    assert len(age_findings(mainnet, view)) == 2
    assert age_findings(mainnet, dataclasses.replace(view, tip_slot=epoch_slot(600, 310))) == []


def test_a_session_of_no_length_is_left_to_the_session_rule(mainnet):
    spec, meta, launch = mainnet
    put(spec, "Sidechain", "SlotsPerEpoch", bytes(4))
    assert age_findings(mainnet, aged(600, 600, 600)) == []
    assert any("genesis Sidechain.SlotsPerEpoch is 0" in message
               for message in messages(lp.check_sessions(spec, meta, launch)))


def test_a_cardano_view_with_no_tip_or_creation_slot_is_an_input_error(mainnet):
    with pytest.raises(lp.InputError, match="no tip"):
        age_findings(mainnet, dataclasses.replace(aged(600, 500, 500), tip_slot=None))
    with pytest.raises(lp.InputError, match="no creation slot for the D-parameter output"):
        age_findings(mainnet, dataclasses.replace(aged(600, 500, 500), created={"permissioned candidates": 5_000_000}))


# ---------------------------------------------------------------------------
# The exposed keys
# ---------------------------------------------------------------------------

def preprod_source_keys() -> list[bytes]:
    """Every 32- or 33-byte key preprod's chain-spec source names in its genesis, read from its byte arrays."""
    source = (HERE.parent.parent / "partnerchain/node/src/chain_spec_preprod.rs").read_text()
    body = source[source.index("pub(crate) fn genesis_patch"):source.index("let authority =")]
    arrays = [bytes(int(byte, 16) for byte in re.findall(r"0x([0-9a-f]{2})", array))
              for array in re.findall(r"\[\s*((?:0x[0-9a-f]{2},\s*)+)\]", body)]
    assert arrays and all(len(raw) in (32, 33) for raw in arrays)
    return arrays


def test_every_key_preprods_genesis_names_is_well_known(spec244, preprod_path, known):
    """Preprod's keys are retired: its genesis accounts and keyholders, authorities' aura, grandpa and cross-chain
    keys, in its chain-spec source, the spec 244 build and the published v6 spec. Pallet accounts are not keys."""
    keys = set(preprod_source_keys())
    for spec in (spec244[0], lp.load_spec(str(preprod_path))):
        keys |= set(spec.accounts()) | {spec.value("Sudo", "Key")} | set(lp.genesis_aura(spec))
        keys |= {voter[:32] for voter in lp.genesis_voters(spec)}
        for cross_chain, aura, grandpa in (lp.genesis_committee(spec) or (0, []))[1]:
            keys |= {cross_chain, lp.blake2_256(cross_chain), aura, grandpa}
    keys = {key for key in keys if key is not None and not key.startswith(b"modl")}
    assert len(keys) >= 20 and keys <= set(known.keys)


def test_every_key_preprods_cardano_candidates_ever_named_is_well_known(known):
    """Every permissioned candidates datum the preprod chain's token was ever held under, as Cardano preprod holds
    them: the authorities preprod seated through Cardano, its retired validators among them."""
    outputs = json.loads((FIXTURES / "preprod-permissioned-candidates.json").read_text())["outputs"]
    keys = {key for output in outputs for candidate in lp.decode_candidates(bytes.fromhex(output["datum"]))
            for key in candidate.keys}
    assert len(outputs) == 7 and len(keys) > 12 and keys <= set(known.keys)


def test_a_retired_preprod_key_in_a_role_is_refused(spec, meta, known):
    keyholder = preprod_source_keys()[1]
    found = dev_key_findings(spec, meta, known, {"roles": {"anchor_signer": [ss58(keyholder)]}})
    assert "[1 dev-keys] roles.anchor_signer[0]: retired preprod key (sr25519)" in found


def test_the_exposed_table_names_no_pallet_account_and_reads_as_a_key_table():
    table = json.loads(lp.EXPOSED_KEYS.read_text())
    assert table["keys"] and all(set(row) == {"label", "scheme", "public"} for row in table["keys"])
    assert not any(bytes.fromhex(row["public"]).startswith(b"modl") for row in table["keys"])
    assert {row["label"] for row in table["keys"]} == {"retired preprod key"}


@pytest.mark.parametrize("item", ["Tasks", "CounterForTasks", "NextTaskId", "PendingGuardianChange", "Approval"])
def test_a_genesis_that_starts_the_root_timelock_queue_is_refused(spec244, item):
    spec, meta = spec244
    put(spec, "RootTimelock", item, bytes(36))
    assert messages(lp.check_genesis_storage(spec, meta)) == [
        f"[4 supply] genesis sets RootTimelock.{item} (1 entry), which a mainnet genesis may not set: "
        "storage outside the genesis allowlist can hold a claim on MATRA that the supply check does not count"]


def test_a_well_known_root_timelock_guardian_is_refused(spec244, known):
    spec, meta = spec244
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


@pytest.mark.parametrize("pallet, item", [("Sudo", "Key"), ("RootTimelock", "Guardian"),
                                          ("OrinqReceipts", "FixedIssuance"), ("Balances", "TotalIssuance")])
@pytest.mark.parametrize("suffix", [b"\x01", bytes(16) + bytes(32)], ids=["a byte", "a map key"])
def test_a_key_under_a_single_values_key_is_refused(mainnet, pallet, item, suffix):
    """The runtime reads a storage value at its 32-byte key alone: a longer key that starts with it is storage no
    runtime code reads, which the genesis hash still covers."""
    spec, meta, _ = mainnet
    key = lp.storage_key(pallet, item) + suffix
    spec.storage[key] = bytes([17]) * 32
    assert messages(lp.check_genesis_storage(spec, meta)) == [
        f"[4 supply] genesis sets storage 0x{key.hex()}, a key under {pallet}.{item}'s that the runtime does not "
        "read, (1 entry), which a mainnet genesis may not set: storage outside the genesis allowlist can hold a "
        "claim on MATRA that the supply check does not count"]


# What build-spec writes for the storage no other rule reads, spelled out here apart from the preflight's table, by
# the rule that refuses another value: the extrinsic index 0; frame_system's two reference-count flags, set, and
# its hash of block 0, 32 bytes of 0x45, as the parent hash and as BlockHash[0]; vesting's storage version V1; a
# native-token observation with no policy, asset name or address; a receipt expiry of 14,400 blocks; settlement's
# pool utilization of 5,000 and 7,500 basis points over no value, its storage version 5, both legacy cutovers at
# block 0, and the runtime's default intent lifetime of 600 blocks, claim lifetime of 28,800 and signer threshold
# of 1; and each pallet's storage version, 5 for Grandpa, 1 for Balances, Motra, Multisig and TeeAttestation, 0 for
# the rest.
BLOCK_HASH_0 = lp.storage_key("System", "BlockHash") + lp.twox_64(bytes(4)) + bytes(4)
PINNED = [
    ("4 supply", ":extrinsic_index", b":extrinsic_index", "00000000"),
    ("4 supply", "System.UpgradedToU32RefCount", lp.storage_key("System", "UpgradedToU32RefCount"), "01"),
    ("4 supply", "System.UpgradedToTripleRefCount", lp.storage_key("System", "UpgradedToTripleRefCount"), "01"),
    ("4 supply", "System.ParentHash", lp.storage_key("System", "ParentHash"), "45" * 32),
    ("4 supply", "System.BlockHash[0]", BLOCK_HASH_0, "45" * 32),
    ("4 supply", "Vesting.StorageVersion", lp.storage_key("Vesting", "StorageVersion"), "01"),
    ("6 checkpoint", "NativeTokenManagement.MainChainScriptsConfiguration",
     lp.storage_key("NativeTokenManagement", "MainChainScriptsConfiguration"), "00" * 30),
    ("2 rewards", "OrinqReceipts.ReceiptExpiryBlocks", lp.storage_key("OrinqReceipts", "ReceiptExpiryBlocks"),
     "40380000"),
    ("11 settlement", "IntentSettlement.PoolUtilization", lp.storage_key("IntentSettlement", "PoolUtilization"),
     "881300004c1d0000" + "00" * 16),
    ("11 settlement", "IntentSettlement.SettlementStorageVersion",
     lp.storage_key("IntentSettlement", "SettlementStorageVersion"), "05000000"),
    ("11 settlement", "IntentSettlement.StcaCutoverBlock", lp.storage_key("IntentSettlement", "StcaCutoverBlock"),
     "00000000"),
    ("11 settlement", "IntentSettlement.PolicyExpireCutoverBlock",
     lp.storage_key("IntentSettlement", "PolicyExpireCutoverBlock"), "00000000"),
    ("11 settlement", "IntentSettlement.IntentTTL", lp.storage_key("IntentSettlement", "IntentTTL"), "58020000"),
    ("11 settlement", "IntentSettlement.ClaimTTL", lp.storage_key("IntentSettlement", "ClaimTTL"), "80700000"),
    ("11 settlement", "IntentSettlement.MinSignerThreshold", lp.storage_key("IntentSettlement", "MinSignerThreshold"),
     "01000000"),
] + [("4 supply", f"the storage version of {pallet}",
      lp.twox_128(pallet.encode()) + lp.twox_128(b":__STORAGE_VERSION__:"),
      {"Grandpa": "0500", "Balances": "0100", "Motra": "0100", "Multisig": "0100", "TeeAttestation": "0100"}.get(
          pallet, "0000"))
     for pallet in ("System", "Timestamp", "Aura", "Grandpa", "Balances", "Sudo", "Multisig", "Utility", "Treasury",
                    "Vesting", "OrinqReceipts", "Motra", "Sidechain", "SessionCommitteeManagement", "BlockRewards",
                    "PalletSession", "Session", "NativeTokenManagement", "IntentSettlement", "TeeAttestation",
                    "Billing", "Oracle", "Recovery", "RootTimelock")]
PINNED_IDS = [name for _, name, _, _ in PINNED]


def pinned_findings(spec, meta) -> list[str]:
    return messages(lp.check_pinned_storage(spec, meta))


def test_the_mainnet_fixture_holds_every_value_the_preflight_pins(mainnet):
    spec, meta, _ = mainnet
    assert {key: spec.storage.get(key, b"unset").hex() for _, _, key, _ in PINNED} == {
        key: value for _, _, key, value in PINNED}
    assert len(PINNED) == 39 and [name for _, name, _, _, _ in lp.pinned_storage(meta)] == PINNED_IDS
    assert pinned_findings(spec, meta) == []


PINNED_EDITS = {"unset": lambda value: None, "a bit flipped": lambda value: bytes([value[0] ^ 1]) + value[1:],
                "a byte more": lambda value: value + bytes(1), "empty": lambda value: b"",
                "all ones": lambda value: bytes([255]) * len(value)}


@pytest.mark.parametrize("rule, name, key, value", PINNED, ids=PINNED_IDS)
@pytest.mark.parametrize("edit", PINNED_EDITS)
def test_a_value_no_other_rule_reads_that_is_not_the_one_build_spec_writes_is_refused(mainnet, rule, name, key,
                                                                                      value, edit):
    spec, meta, _ = mainnet
    edited = PINNED_EDITS[edit](bytes.fromhex(value))
    if edited is None:
        del spec.storage[key]
    else:
        spec.storage[key] = edited
    shown = "sets no" if edited is None else f"stores 0x{edited.hex()} as"
    found = pinned_findings(spec, meta)
    assert len(found) == 1 and found[0].startswith(
        f"[{rule}] genesis {shown} {name}, not the 0x{value} build-spec writes: ")


def test_a_storage_version_below_the_code_or_above_it_names_the_migrations_it_misleads(mainnet):
    spec, meta, _ = mainnet
    key = lp.twox_128(b"Balances") + lp.twox_128(b":__STORAGE_VERSION__:")
    for version in (0, 99):
        spec.storage[key] = version.to_bytes(2, "little")
        assert pinned_findings(spec, meta) == [
            f"[4 supply] genesis stores 0x{version.to_bytes(2, 'little').hex()} as the storage version of Balances, "
            "not the 0x0100 build-spec writes: a later runtime upgrade runs Balances's migrations against storage "
            "already in its layout, or skips them"]


def test_a_block_hash_of_any_block_but_the_first_is_refused(mainnet):
    spec, meta, _ = mainnet
    for number in (1, 5):
        index = number.to_bytes(4, "little")
        spec.storage[lp.storage_key("System", "BlockHash") + lp.twox_64(index) + index] = bytes([17]) * 32
    assert pinned_findings(spec, meta) == [
        "[4 supply] genesis sets 2 System.BlockHash entries besides block 0's, the one build-spec writes: a new "
        "chain has no earlier block to name"]


@pytest.mark.parametrize("item, constant", [("IntentTTL", "DefaultIntentTTL"), ("ClaimTTL", "DefaultClaimTTL"),
                                            ("MinSignerThreshold", "DefaultMinSignerThreshold")])
def test_settlements_lifetimes_and_threshold_are_held_to_the_runtimes_own_defaults(mainnet, item, constant):
    spec, meta, _ = mainnet
    meta.constants[("IntentSettlement", constant)] = (77).to_bytes(4, "little")
    stored = spec.value("IntentSettlement", item)
    assert pinned_findings(spec, meta) == [
        f"[11 settlement] genesis stores 0x{stored.hex()} as IntentSettlement.{item}, not the 0x4d000000 build-spec "
        "writes: settlement runs on other parameters than the runtime's defaults, which build-spec writes"]
    del meta.constants[("IntentSettlement", constant)]
    assert pinned_findings(spec, meta) == [
        f"[11 settlement] the runtime metadata declares no default the preflight can read for IntentSettlement.{item}"
        ": what build-spec writes for it is unknown here"]


# ---------------------------------------------------------------------------
# Kupo: what Cardano holds
# ---------------------------------------------------------------------------

class Kupo:
    """A local server that answers like Kupo: /health, /matches/<pattern>?unspent, /datums/<hash>."""

    def __init__(self):
        self.routes, self.accept = {}, []
        self.routes["/health"] = {"connection_status": "connected", "most_recent_checkpoint": KUPO_TIP - 10,
                                  "most_recent_node_tip": KUPO_TIP}
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
    return legacy_datum([(cross_chain_key(), aura, gran) for aura, gran in zip(aura_keys(spec), grandpa)])


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


def test_cardano_view_reads_kupos_tip_and_when_each_committee_output_was_created(spec, kupo):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    view = lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})
    assert (view.tip_slot, view.created) == (KUPO_TIP, {"D-parameter": CREATED, "permissioned candidates": CREATED})


@COMMITTEE_TOKENS
@pytest.mark.parametrize("created_at", [None, {"slot_no": "1"}, {}], ids=["none", "a string", "no slot"])
def test_a_committee_output_kupo_gives_no_creation_slot_is_an_input_error(spec, kupo, policy, what, created_at):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    route = token_route(spec, policy)
    kupo.routes[route] = [dict(kupo.routes[route][0], created_at=created_at)]
    with pytest.raises(lp.InputError, match=f"Kupo gives the {what} output .* no created_at slot"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


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


@pytest.mark.parametrize("seconds", [-600, 0, 600])
def test_a_kupo_whose_nodes_tip_is_within_ten_minutes_of_the_clock_is_read(spec, kupo, monkeypatch, seconds):
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    monkeypatch.setattr(lp, "wall_clock", lambda: SHELLEY_START + KUPO_TIP - 4_492_800 + seconds)
    assert lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}}).tip_slot == KUPO_TIP


@pytest.mark.parametrize("seconds, shown", [(601, "601 seconds behind"), (3 * 86_400, "259200 seconds behind"),
                                            (-601, "601 seconds ahead of")])
def test_a_kupo_whose_nodes_tip_is_not_cardanos_now_is_an_input_error(spec, kupo, monkeypatch, seconds, shown):
    """Kupo within a few slots of a node that has itself stopped following Cardano lists outputs as they stood at
    that node's tip, and puts the launch in the epoch of that tip."""
    kupo.serve(spec, None, genesis_candidates_datum(spec))
    monkeypatch.setattr(lp, "wall_clock", lambda: SHELLEY_START + KUPO_TIP - 4_492_800 + seconds)
    with pytest.raises(lp.InputError, match=f"^the tip of Kupo's node, slot {KUPO_TIP}, is {shown} this host's "
                                            "clock, more than 600: its node is not following Cardano mainnet"):
        lp.cardano_view(kupo.url, spec, {"supply": {"genesis_lock": LOCK}})


def test_the_clock_the_tip_is_held_to_is_this_hosts():
    assert abs(HOST_CLOCK() - time.time()) < 5


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
            for i, member in enumerate(entry["members"]) if lp.is_multisig(member)]


def delays(*blocks: int) -> bytes:
    return b"".join(block.to_bytes(4, "little") for block in blocks)


def timelock_launch(sudo_members, guardian) -> dict:
    return {"roles": {"sudo": [msig(2, *sudo_members)], "guardian": [guardian]}}


@pytest.fixture
def guarded(spec244):
    """The spec 244 preprod genesis with Root held by a 2-of-3 multisig of fresh
    keys, and the timelock guarded by a 2-of-3 multisig of other fresh keys at
    the mainnet delays."""
    spec, meta = spec244
    sudo, guardian = [fresh_account() for _ in range(3)], [fresh_account() for _ in range(3)]
    put(spec, "Sudo", "Key", lp.multisig_account(sudo, 2))
    put(spec, "RootTimelock", "Guardian", lp.multisig_account(guardian, 2))
    put(spec, "RootTimelock", "Delays", delays(*MAINNET_DELAYS))
    return spec, meta, sudo, guardian


def guardian_findings(spec, meta, sudo, entry) -> list[str]:
    """Rule 7's guardian check, with `entry` stored in genesis as the guardian and declared as roles.guardian."""
    put(spec, "RootTimelock", "Guardian", lp.role_account(entry))
    return messages(lp.check_guardian(spec, meta, timelock_launch(sudo, entry), KNOWN))


def delay_findings(spec, meta, *blocks: int) -> list[str]:
    put(spec, "RootTimelock", "Delays", delays(*blocks))
    return messages(lp.check_delays(spec, meta))


def test_the_spec244_metadata_declares_the_mainnet_delays_and_their_ceiling(spec244):
    _, meta = spec244
    assert meta.constants[("RootTimelock", "DefaultDelays")] == delays(*MAINNET_DELAYS)
    assert meta.constants[("RootTimelock", "MaxDelay")] == MAX_DELAY.to_bytes(4, "little")


def test_a_guardian_apart_from_the_sudo_key_at_the_mainnet_delays_passes(guarded):
    spec, meta, sudo, guardian = guarded
    assert lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian)), KNOWN) == []
    assert lp.check_delays(spec, meta) == []


def test_the_spec244_preprod_timelock_is_refused_on_mainnet(spec244):
    spec, meta = spec244
    assert spec.value("Sudo", "Key") == lp.multisig_account(PREPROD_KEYHOLDERS, 2)
    launch = timelock_launch(PREPROD_KEYHOLDERS, msig(3, *PREPROD_KEYHOLDERS))
    assert messages(lp.check_guardian(spec, meta, launch, KNOWN)) == [
        "[7 timelock] roles.guardian[0]: the keys anyone can sign as, at roles.guardian[0].members[0] and "
        "roles.guardian[0].members[1] and roles.guardian[0].members[2], meet its threshold, so anyone can veto Root's "
        "queued calls or co-sign them early"] + [
        f"[7 timelock] roles.guardian[0].members[{i}] {ss58(key)} is also roles.sudo[0].members[{i}]{SHARED}"
        for i, key in enumerate(PREPROD_KEYHOLDERS)]
    assert messages(lp.check_delays(spec, meta)) == [
        f"[7 timelock] RootTimelock.Delays holds {name} calls {blocks} blocks, below the {least} the runtime sets "
        "for mainnet" for name, blocks, least in zip(("recovery", "standard", "long"), TESTNET_DELAYS, MAINNET_DELAYS)]


def test_a_genesis_with_no_guardian_is_refused(guarded):
    """The runtime's genesis builder lets a dev sudo key go unguarded; a mainnet launch has no dev key to excuse it."""
    spec, meta, sudo, guardian = guarded
    del spec.storage[lp.storage_key("RootTimelock", "Guardian")]
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian)), KNOWN)) == [NO_GUARDIAN]


@pytest.mark.parametrize("count", [None, 0, 2])
def test_a_guardian_not_declared_as_one_entry_is_refused(guarded, count):
    spec, meta, sudo, guardian = guarded
    launch = timelock_launch(sudo, msig(2, *guardian))
    if count is None:
        del launch["roles"]["guardian"]
    else:
        launch["roles"]["guardian"] = [msig(2, *guardian)] * count
    assert messages(lp.check_guardian(spec, meta, launch, KNOWN)) == [UNDECLARED_GUARDIAN]


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


def test_a_guardian_one_key_meets_with_a_key_anyone_holds_is_refused(guarded):
    spec, meta, sudo, _ = guarded
    holder = fresh_account()
    assert guardian_findings(spec, meta, sudo, msig(2, holder, BASEPOINT)) == [
        helped_holder("7 timelock", "roles.guardian[0]", holder, "members[0]", ["members[1]"], GUARDIAN_POWER)]


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
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, msig(2, *guardian)), KNOWN)) == [
        f"[7 timelock] RootTimelock.Guardian {ss58(hidden)} is not the account roles.guardian declares: "
        "who can veto Root is unchecked"]


def test_a_guardian_multisig_with_a_dev_member_is_refused(guarded, known):
    """Genesis holds only the multisig's account, a hash; rule 1 finds the dev key among the declared members, and
    rule 7 that anyone can sign as it, so either other member vetoes alone."""
    spec, meta, sudo, guardian = guarded
    entry = msig(2, ALICE, *guardian[:2])
    assert guardian_findings(spec, meta, sudo, entry) == [
        helped_holder("7 timelock", "roles.guardian[0]", key, f"members[{i}]", ["members[0]"], GUARDIAN_POWER)
        for i, key in sorted(enumerate(guardian[:2], 1), key=lambda member: member[1])]
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
    assert messages(lp.check_guardian(spec, meta, {"roles": {"guardian": [entry]}}, KNOWN)) == [
        f"[7 timelock] roles.guardian[0].members[0] {ss58(key)} is also Sudo.Key{SHARED}"]


def test_a_guardian_key_that_does_not_decode_leaves_its_refusal_to_rule_1(guarded):
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": ["//Bob", ss58(guardian[0])]}
    assert lp.check_guardian(spec, meta, timelock_launch(sudo, entry), KNOWN) == []


def test_a_guardian_key_that_does_not_decode_leaves_the_rest_of_rule_7_standing(guarded):
    spec, meta, sudo, guardian = guarded
    entry = {"threshold": 2, "members": ["//Bob", ss58(guardian[0])]}
    launch = timelock_launch(sudo, entry)
    put(spec, "RootTimelock", "Guardian", spec.value("Sudo", "Key"))
    assert messages(lp.check_guardian(spec, meta, launch, KNOWN)) == [
        "[7 timelock] RootTimelock.Guardian is Sudo.Key: the sudo key would veto and co-sign its own Root calls"]
    del spec.storage[lp.storage_key("RootTimelock", "Guardian")]
    assert messages(lp.check_guardian(spec, meta, launch, KNOWN)) == [NO_GUARDIAN]
    oversized = {"threshold": 2, "members": ["//Bob", *(ss58(fresh_account()) for _ in range(10))]}
    assert messages(lp.check_guardian(spec, meta, timelock_launch(sudo, oversized), KNOWN)) == [
        NO_GUARDIAN, too_many_signatories("7 timelock", "roles.guardian[0]", 11)]


def test_a_sudo_key_that_does_not_decode_leaves_the_guardian_checked(guarded):
    spec, meta, sudo, guardian = guarded
    hidden = lp.multisig_account([ALICE, *guardian[:2]], 2)
    put(spec, "RootTimelock", "Guardian", hidden)
    launch = {"roles": {"sudo": [{"threshold": 2, "members": ["//Alice", ss58(sudo[0])]}],
                        "guardian": [msig(2, *guardian)]}}
    assert messages(lp.check_guardian(spec, meta, launch, KNOWN)) == [
        f"[7 timelock] RootTimelock.Guardian {ss58(hidden)} is not the account roles.guardian declares: "
        "who can veto Root is unchecked"]


def test_the_mainnet_delays_and_delays_up_to_max_delay_pass(spec244):
    spec, meta = spec244
    assert delay_findings(spec, meta, *MAINNET_DELAYS) == []
    assert delay_findings(spec, meta, MAX_DELAY, MAX_DELAY, MAX_DELAY) == []


@pytest.mark.parametrize("index, name", enumerate(("recovery", "standard", "long")))
def test_a_delay_one_block_below_the_mainnet_delay_is_refused(spec244, index, name):
    spec, meta = spec244
    blocks = [*MAINNET_DELAYS]
    blocks[index] -= 1
    assert delay_findings(spec, meta, *blocks) == [
        f"[7 timelock] RootTimelock.Delays holds {name} calls {blocks[index]} blocks, below the "
        f"{MAINNET_DELAYS[index]} the runtime sets for mainnet"]


@pytest.mark.parametrize("long", [MAX_DELAY + 1, 2**32 - 1])
def test_a_long_delay_above_max_delay_is_refused(spec244, long):
    spec, meta = spec244
    assert delay_findings(spec, meta, DAYS, 7 * DAYS, long) == [
        f"[7 timelock] RootTimelock.Delays holds long calls {long} blocks, above the runtime's MaxDelay {MAX_DELAY}: "
        "a guardian change, or a cut to the long delay itself, would wait longer than the runtime lets any delay be"]


def test_delays_out_of_the_runtime_order_are_refused(spec244):
    spec, meta = spec244
    assert delay_findings(spec, meta, 20 * DAYS, 7 * DAYS, 30 * DAYS) == [
        f"[7 timelock] RootTimelock.Delays (recovery {20 * DAYS}, standard {7 * DAYS}, long {30 * DAYS} blocks) "
        "breaks the order 0 < recovery <= standard <= long that the runtime's genesis builder asserts"]


def test_a_standard_delay_above_the_long_delay_is_refused_within_every_other_bound(spec244):
    """Each delay at least its mainnet delay and long at most MaxDelay: only the order refuses."""
    spec, meta = spec244
    assert delay_findings(spec, meta, DAYS, 60 * DAYS, 30 * DAYS) == [
        f"[7 timelock] RootTimelock.Delays (recovery {DAYS}, standard {60 * DAYS}, long {30 * DAYS} blocks) "
        "breaks the order 0 < recovery <= standard <= long that the runtime's genesis builder asserts"]


def test_zero_delays_are_refused(spec244):
    spec, meta = spec244
    found = delay_findings(spec, meta, 0, 0, 0)
    assert len(found) == 4
    assert "[7 timelock] RootTimelock.Delays holds recovery calls 0 blocks, below the 14400 the runtime sets for " \
           "mainnet" in found
    assert found[-1].startswith("[7 timelock] RootTimelock.Delays (recovery 0, standard 0, long 0 blocks) breaks")


def test_the_bounds_are_the_runtime_constants(spec244):
    spec, meta = spec244
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
def test_a_runtime_that_hides_its_timelock_bounds_is_refused(spec244, constants):
    spec, meta = spec244
    for name, value in constants.items():
        if value is None:
            del meta.constants[("RootTimelock", name)]
        else:
            meta.constants[("RootTimelock", name)] = value
    assert messages(lp.check_delays(spec, meta)) == [HIDDEN_BOUNDS]


def test_a_runtime_with_no_root_timelock_is_refused(spec, meta):
    assert messages(lp.check_delays(spec, meta)) == [HIDDEN_BOUNDS]
    assert NO_GUARDIAN in messages(lp.check_guardian(spec, meta, {"roles": {}}, KNOWN))


@pytest.mark.parametrize("raw", [b"", bytes(11), bytes(13), bytes(24)], ids=lambda raw: f"{len(raw)} bytes")
def test_delays_that_do_not_decode_are_refused(spec244, raw):
    spec, meta = spec244
    put(spec, "RootTimelock", "Delays", raw)
    assert messages(lp.check_delays(spec, meta)) == [
        f"[7 timelock] RootTimelock.Delays is {len(raw)} bytes, not three 4-byte block counts"]


def test_a_genesis_that_stores_no_delays_is_refused(spec244):
    spec, meta = spec244
    del spec.storage[lp.storage_key("RootTimelock", "Delays")]
    assert messages(lp.check_delays(spec, meta)) == [
        "[7 timelock] genesis sets no RootTimelock.Delays, which every genesis the runtime builds sets: how long "
        "Root's calls wait is unchecked"]


# ---------------------------------------------------------------------------
# Rule 10: every multisig member's holder proves possession of its key
# ---------------------------------------------------------------------------

def possession_findings(spec: lp.Spec, launch: dict) -> list[str]:
    return messages(lp.check_possession(spec, launch))


def bare(where: str) -> str:
    return (f"[10 possession] {where} is a bare key: a multisig member is a key given with its holder's pop, "
            '{"key": ..., "pop": ...}, or a multisig declared by its members, since an address no one proves to hold '
            "can be a multisig no one declared")


def no_pop(where: str, role: str, index: str) -> str:
    return (f"[10 possession] {where} gives no pop: its holder has not signed its challenge (challenge --role {role} "
            f"--index {index}), so no one has shown they hold its key")


def unproven(where: str, scheme: str, role: str, index: str) -> str:
    return (f"[10 possession] {where}: its pop is not an {scheme} signature by its key of its challenge (challenge "
            f"--role {role} --index {index}), which binds this chain, its genesis, the launch manifest's "
            "genesis-bound fields, and its role, position and key: another key signed it, its holder signed for "
            "another launch, role or position, or a genesis-bound field changed since")


def nested_multisig() -> dict:
    """A 2-of-3 whose third member is a 2-of-2, every key fresh."""
    return {"threshold": 2, "members": [ss58(fresh_account()), ss58(fresh_account()),
                                        msig(2, fresh_account(), fresh_account())]}


def leaves(entry) -> list:
    return [leaf for _, _, leaf in lp.role_leaves(entry, "")]


def test_a_nested_multisig_whose_every_key_proves_possession_passes(spec):
    launch = prove({"roles": {"sudo": [nested_multisig()], "guardian": [msig(2, *(fresh_account() for _ in range(3)))],
                              "endowed": [ss58(fresh_account()), msig(1, fresh_account(), fresh_ecdsa_key())]}}, spec)
    proven = [leaf for role in ("sudo", "guardian") for leaf in leaves(launch["roles"][role][0])]
    proven += leaves(launch["roles"]["endowed"][1])
    assert len(proven) == 9 and all(set(leaf) == {"key", "pop"} for leaf in proven)
    assert possession_findings(spec, launch) == []


def test_a_member_given_as_a_bare_key_is_refused_in_any_role_at_any_depth(spec):
    sudo, endowed = nested_multisig(), msig(1, fresh_account(), stranger())
    sudo["members"][2]["members"][1] = ss58(stranger())
    launch = prove({"roles": {"sudo": [sudo], "endowed": [endowed]}}, spec)
    assert possession_findings(spec, launch) == [bare("roles.endowed[0].members[1]"),
                                                 bare("roles.sudo[0].members[2].members[1]")]


# The address of a multisig no one declared: no secret signs for it, so it can prove nothing.
def test_a_multisig_address_given_as_a_member_cannot_prove_possession(spec):
    hidden = lp.multisig_account([fresh_account(), fresh_account()], 1)
    launch = prove({"roles": {"sudo": [{"threshold": 2, "members": [
        ss58(fresh_account()), {"key": ss58(hidden), "pop": "0x" + os.urandom(64).hex()}]}]}}, spec)
    assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[1]", "sr25519", "sudo", "0 1")]


def test_a_member_given_with_no_pop_is_refused(spec):
    launch = prove({"roles": {"guardian": [{"threshold": 2, "members": [
        ss58(fresh_account()), ss58(fresh_account()), {"key": ss58(stranger())}]}]}}, spec)
    assert possession_findings(spec, launch) == [no_pop("roles.guardian[0].members[2]", "guardian", "0 2")]


def another_genesis(spec: lp.Spec) -> lp.Spec:
    other = lp.Spec(copy.deepcopy(spec.doc), dict(spec.storage), spec.source)
    put(other, "Sudo", "Key", fresh_account())
    return other


def renamed(spec: lp.Spec, **fields) -> lp.Spec:
    return lp.Spec(dict(spec.doc, **fields), spec.storage, spec.source)


def its_key(launch: dict) -> bytes:
    return member_key(launch, "sudo", (0, 1))


# The challenge the member at roles.sudo[0].members[1] signs, for another launch, role, position or key than its own.
OTHER_CHALLENGES = {
    "another genesis-bound manifest": lambda spec, launch: challenge(spec, dict(launch, slots_per_epoch=60), "sudo",
                                                                     (0, 1)),
    "another role": lambda spec, launch: challenge(spec, launch, "guardian", (0, 1), its_key(launch)),
    "another member index": lambda spec, launch: challenge(spec, launch, "sudo", (0, 2), its_key(launch)),
    "another multisig index": lambda spec, launch: challenge(spec, launch, "sudo", (1, 1), its_key(launch)),
    "a nested position": lambda spec, launch: challenge(spec, launch, "sudo", (0, 1, 0), its_key(launch)),
    "another key": lambda spec, launch: challenge(spec, launch, "sudo", (0, 1), fresh_account()),
    "another chain name": lambda spec, launch: challenge(renamed(spec, name="Materios"), launch, "sudo", (0, 1)),
    "another chain id": lambda spec, launch: challenge(renamed(spec, id="materios"), launch, "sudo", (0, 1)),
    "another genesis": lambda spec, launch: challenge(another_genesis(spec), launch, "sudo", (0, 1)),
    "the first version's domain": lambda spec, launch: (b"materios-launch-pop-v1"
                                                        + challenge(spec, launch, "sudo", (0, 1))[len(POP_DOMAIN):]),
    "the whole manifest's hash in place of its genesis-bound content's": lambda spec, launch: (
        launch_context(spec, launch)[:-32] + lp.launch_manifest_hash(launch)
        + challenge(spec, launch, "sudo", (0, 1))[len(launch_context(spec, launch)):]),
    "the challenge wrapped as polkadot.js signRaw wraps it": lambda spec, launch: (
        b"<Bytes>" + challenge(spec, launch, "sudo", (0, 1)) + b"</Bytes>"),
}


@pytest.mark.parametrize("other", OTHER_CHALLENGES.values(), ids=OTHER_CHALLENGES.keys())
def test_a_pop_its_holder_signed_for_another_launch_role_or_position_is_refused(spec, other):
    member = fresh_account()
    launch = prove({"roles": {"sudo": [msig(2, fresh_account(), member, fresh_account())]}}, spec)
    launch["roles"]["sudo"][0]["members"][1]["pop"] = "0x" + KEYHOLDERS[member](other(spec, launch)).hex()
    assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[1]", "sr25519", "sudo", "0 1")]


# What stands in a member's pop in place of its holder's signature of its own challenge.
FORGERIES = {
    "another key's signature of its challenge": lambda member, message: KEYHOLDERS[fresh_account()](message),
    "random bytes": lambda member, message: os.urandom(64),
    "zeros": lambda member, message: bytes(64),
    "its signature cut short": lambda member, message: KEYHOLDERS[member](message)[:63],
    "its signature with a byte more": lambda member, message: KEYHOLDERS[member](message) + b"\0",
    "nothing": lambda member, message: b"",
}


@pytest.mark.parametrize("forge", FORGERIES.values(), ids=FORGERIES.keys())
def test_a_pop_that_is_not_its_keys_signature_of_its_challenge_is_refused(spec, forge):
    member = fresh_account()
    launch = prove({"roles": {"sudo": [msig(2, fresh_account(), member)]}}, spec)
    message = challenge(spec, launch, "sudo", (0, 1))
    launch["roles"]["sudo"][0]["members"][1]["pop"] = "0x" + forge(member, message).hex()
    assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[1]", "sr25519", "sudo", "0 1")]


def no_secret(where: str) -> str:
    return (f"[10 possession] {where} is the all-zero key, whose sr25519 signature of any message needs no secret: "
            "its pop shows no one holds it")


# schnorrkel, as py-sr25519-bindings and sp_core run it, verifies the all-zero key's signature that needs no secret.
@pytest.mark.parametrize("spelling", [ss58, lambda key: "0x" + key.hex()], ids=["SS58", "0x-hex"])
def test_the_all_zero_key_cannot_prove_possession(spec, spelling):
    zero = {"key": spelling(ZERO_KEY), "pop": "0x" + NO_SECRET_POP.hex()}
    sudo = nested_multisig()
    sudo["members"][2]["members"][1] = zero
    launch = prove({"roles": {"sudo": [sudo], "guardian": [{"threshold": 2, "members": [
        ss58(fresh_account()), dict(zero), ss58(fresh_account())]}]}}, spec)
    for role, position in (("guardian", (0, 1)), ("sudo", (0, 2, 1))):
        assert sr25519.verify(NO_SECRET_POP, challenge(spec, launch, role, position), ZERO_KEY)
    assert possession_findings(spec, launch) == [no_secret("roles.guardian[0].members[1]"),
                                                 no_secret("roles.sudo[0].members[2].members[1]")]


def test_two_members_pops_swapped_are_refused(spec):
    launch = prove({"roles": {"sudo": [msig(2, fresh_account(), fresh_account())]}}, spec)
    first, second = launch["roles"]["sudo"][0]["members"]
    first["pop"], second["pop"] = second["pop"], first["pop"]
    assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[0]", "sr25519", "sudo", "0 0"),
                                                 unproven("roles.sudo[0].members[1]", "sr25519", "sudo", "0 1")]


# A 33-byte key is ECDSA's, which the manifest admits: sp_core's ecdsa recovers the signer from blake2-256 of the
# message and the signature's recovery id, and compares it with the key.
def test_an_ecdsa_member_proves_possession_as_sp_core_verifies_it(spec):
    member = fresh_ecdsa_key()
    launch = prove({"roles": {"sudo": [msig(2, fresh_account(), member)]}}, spec)
    assert launch["roles"]["sudo"][0]["members"][1]["key"] == "0x" + member.hex()
    assert possession_findings(spec, launch) == []
    signature = bytes.fromhex(launch["roles"]["sudo"][0]["members"][1]["pop"][2:])
    for pop in (signature[:64] + bytes([signature[64] ^ 1]), signature[:64], KEYHOLDERS[fresh_account()](b"")):
        launch["roles"]["sudo"][0]["members"][1]["pop"] = "0x" + pop.hex()
        assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[1]", "ECDSA", "sudo", "0 1")]


# The manifest says no more of a 32-byte key than that it is an account: it is read as sr25519's, Substrate's default.
def test_an_ed25519_signature_does_not_prove_possession_of_a_32_byte_key(spec):
    signer = signing.SigningKey.generate()
    launch = prove({"roles": {"sudo": [{"threshold": 2, "members": [
        ss58(fresh_account()), {"key": ss58(signer.verify_key.encode())}]}]}}, spec)
    launch["roles"]["sudo"][0]["members"][1]["pop"] = "0x" + signer.sign(
        challenge(spec, launch, "sudo", (0, 1))).signature.hex()
    assert possession_findings(spec, launch) == [unproven("roles.sudo[0].members[1]", "sr25519", "sudo", "0 1")]


def test_collecting_the_pops_leaves_the_launch_manifest_hash_as_it_was(spec):
    keyed = {"roles": {"sudo": [{"threshold": 2, "members": [
        {"key": ss58(fresh_account())}, {"threshold": 2, "members": [{"key": ss58(fresh_account())},
                                                                   {"key": role_key(fresh_ecdsa_key())}]}]}]}}
    proven = prove(keyed, spec)
    assert all("pop" in leaf for leaf in leaves(proven["roles"]["sudo"][0]))
    assert lp.launch_manifest_hash(proven) == lp.launch_manifest_hash(keyed)
    key = signing.SigningKey.generate()
    assert lp.check_checkpoint(spec, proven, lp.signed_manifest(spec, keyed, key), [pub(key)]) == []
    rekeyed = copy.deepcopy(proven)
    rekeyed["roles"]["sudo"][0]["members"][0]["key"] = ss58(fresh_account())
    assert lp.launch_manifest_hash(rekeyed) != lp.launch_manifest_hash(proven)


def test_a_role_entry_that_is_not_a_multisig_owes_no_pop(spec):
    launch = {"roles": {"anchor_signer": [ss58(stranger())], "endowed": [ss58(stranger())]}}
    assert possession_findings(spec, launch) == []


# Rules 1 and 7 read a member given with its pop as its key.
@pytest.mark.parametrize("build", ONE_HOLDER_MULTISIGS, ids=lambda build: build.__name__)
def test_rule_1_reads_a_member_given_with_its_pop_as_its_key(spec, meta, known, build):
    entry, holders = build()
    proven = prove(sudo_launch(entry), spec)["roles"]["sudo"][0]
    assert any(isinstance(leaf, dict) for leaf in leaves(proven))
    assert sudo_findings(spec, meta, known, proven) == [
        lone_holder("1 dev-keys", "roles.sudo[0]", key, paths, SUDO_POWER) for key, paths in sorted(holders)]


# The spec 244 fixture holds no code to hash its genesis with, so the preprod v6 spec's challenges stand in.
def test_a_guardian_whose_members_are_given_with_their_pops_has_no_nested_multisig(spec, guarded):
    timelocked, meta, sudo, guardian = guarded
    entry = prove(timelock_launch(sudo, msig(2, *guardian)), spec)["roles"]["guardian"][0]
    assert all(set(member) == {"key", "pop"} for member in entry["members"])
    assert guardian_findings(timelocked, meta, sudo, entry) == []


KEY, POP = ss58(stranger()), "0x" + "cd" * 64


def with_member(member) -> dict:
    return {"roles": {"sudo": [{"threshold": 2, "members": [ss58(fresh_account()), member]}]}, "supply": VALID_LOCK}


def test_a_member_given_with_its_pop_is_read():
    lp.validate_launch(with_member({"key": KEY, "pop": POP}))
    lp.validate_launch(with_member({"key": KEY}))


@spelled(MISSPELLINGS)
def test_a_pop_in_another_spelling_is_an_input_error(misspell):
    with pytest.raises(lp.InputError, match=rf"^roles\.sudo\[0\]\.members\[1\]\.pop {MISSPELLED}"):
        lp.validate_launch(with_member({"key": KEY, "pop": misspell("cd" * 64)}))


@spelled(HEX_KEY_MISSPELLINGS)
def test_a_member_key_given_with_its_pop_in_another_spelling_of_hex_is_an_input_error(misspell):
    with pytest.raises(lp.InputError, match=rf"^roles\.sudo\[0\]\.members\[1\]\.key {MISSPELLED}"):
        lp.validate_launch(with_member({"key": misspell(DIGITS), "pop": POP}))


@pytest.mark.parametrize("member", [
    {"key": KEY, "pop": POP, "scheme": "sr25519"}, {"key": KEY, "pop": None}, {"key": 7, "pop": POP},
    {"key": KEY, "pop": [POP]},
], ids=["an unknown field", "a null pop", "a key that is not a string", "a pop that is not a string"])
def test_a_member_key_given_in_another_shape_is_an_input_error(member):
    with pytest.raises(lp.InputError, match=re.escape(
            "roles.sudo[0].members[1] must hold its key and, once its holder signs, its pop, each a string")):
        lp.validate_launch(with_member(member))


def test_a_pop_for_a_role_entry_that_is_no_multisig_member_is_an_input_error():
    with pytest.raises(lp.InputError, match=re.escape(
            "roles.anchor_signer[0] gives a key with a pop: a role entry is a public key or a multisig, and a pop is "
            "given for a multisig's member")):
        lp.validate_launch({"roles": {"anchor_signer": [{"key": KEY, "pop": POP}]}, "supply": VALID_LOCK})


# ---------------------------------------------------------------------------
# Rule 11: the Cardano network settlement binds
# ---------------------------------------------------------------------------

# Cardano mainnet as its published environment gives it (book.world.dev.cardano.org/environments/mainnet), and
# Cardano preprod as the preprod runtime has bound it.
CARDANO_MAINNET_MAGIC = 764824073
CARDANO_MAINNET_SHELLEY = bytes.fromhex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81")
CARDANO_PREPROD_SHELLEY = bytes.fromhex("162d29c4e1cf6b8a84f2d692e67a3ac6bc7851bc3e6e4afe64d15778bed8bd86")
AEGIS_POLICY = bytes([0x5a]) * 28
SETTLEMENT = {"aegis_policy_v1_script_hash": "0x" + AEGIS_POLICY.hex()}
# A launch whose Aegis policy is applied to the chain's own genesis hash: genesis binds none, and Root binds it with
# IntentSettlement.bind_aegis_policy_v1 after launch.
BOUND_AFTER_GENESIS = {"aegis_policy_v1_script_hash": None}


def cardano_ids(magic: int = CARDANO_MAINNET_MAGIC, shelley: bytes = CARDANO_MAINNET_SHELLEY,
                aegis: bytes = AEGIS_POLICY) -> bytes:
    """IntentSettlement.CardanoIds as SCALE encodes it: the network magic, a u32, then the Shelley genesis hash
    and the aegis_policy_v1 script hash."""
    return magic.to_bytes(4, "little") + shelley + aegis


def settles_on_mainnet(spec: lp.Spec) -> None:
    put(spec, "IntentSettlement", "CardanoIds", cardano_ids())


def with_cardano_ids(metadata_v14: dict) -> dict:
    """The fixture metadata plus the item a runtime that stores settlement's Cardano network declares."""
    v14 = copy.deepcopy(metadata_v14)
    pallet = next(p for p in v14["pallets"] if p["name"] == "IntentSettlement")
    pallet["storage"]["entries"].append({"name": "CardanoIds"})
    return v14


def test_the_preflight_holds_cardano_mainnet_to_its_published_shelley_genesis():
    """The networkMagic of mainnet's published shelley-genesis.json, and that file's blake2b-256, which mainnet's
    config.json publishes as ShelleyGenesisHash."""
    shelley = (FIXTURES / "cardano-mainnet-shelley-genesis.json").read_bytes()
    config = json.loads((FIXTURES / "cardano-mainnet-config.json").read_text())
    assert json.loads(shelley)["networkMagic"] == lp.CARDANO_MAINNET_NETWORK_MAGIC == CARDANO_MAINNET_MAGIC
    assert lp.blake2_256(shelley) == lp.CARDANO_MAINNET_SHELLEY_GENESIS_HASH == CARDANO_MAINNET_SHELLEY
    assert config["ShelleyGenesisHash"] == CARDANO_MAINNET_SHELLEY.hex()


def test_a_genesis_settling_against_cardano_mainnet_and_the_declared_aegis_policy_passes(spec):
    settles_on_mainnet(spec)
    assert lp.check_settlement(spec, {"settlement": SETTLEMENT}) == []


def test_a_genesis_binding_no_aegis_policy_passes_where_the_launch_binds_it_after_genesis(spec):
    put(spec, "IntentSettlement", "CardanoIds", cardano_ids(aegis=bytes(28)))
    assert lp.check_settlement(spec, {"settlement": BOUND_AFTER_GENESIS}) == []


def test_a_genesis_binding_an_aegis_policy_is_refused_where_the_launch_binds_it_after_genesis(spec):
    settles_on_mainnet(spec)
    assert messages(lp.check_settlement(spec, {"settlement": BOUND_AFTER_GENESIS})) == [
        f"[11 settlement] genesis IntentSettlement.CardanoIds binds aegis_policy_v1 script hash 0x{AEGIS_POLICY.hex()}"
        ", where the launch declares the policy bound after genesis (null): bind_aegis_policy_v1 binds one only "
        "while none is bound, so the policy deployed on the chain's genesis hash could not be bound"]


AGAINST = ("every voucher the committee signs binds it and all settlement and expiry evidence must name its Shelley "
           "genesis, so the chain settles against another Cardano network than the mainnet it launches on")


@pytest.mark.parametrize("stored, refusals", [
    (cardano_ids(magic=1, shelley=CARDANO_PREPROD_SHELLEY, aegis=bytes(28)), [
        f"genesis IntentSettlement.CardanoIds holds network magic 1, not Cardano mainnet's 764824073: {AGAINST}",
        f"genesis IntentSettlement.CardanoIds holds Shelley genesis hash 0x{CARDANO_PREPROD_SHELLEY.hex()}, not "
        f"Cardano mainnet's 0x{CARDANO_MAINNET_SHELLEY.hex()}: {AGAINST}",
        f"genesis IntentSettlement.CardanoIds binds no aegis_policy_v1 script hash, not the 0x{AEGIS_POLICY.hex()} the "
        "launch declares deployed: every voucher the committee signs binds it (a launch that binds it after genesis "
        "declares null)"]),
    (cardano_ids(magic=1), [
        f"genesis IntentSettlement.CardanoIds holds network magic 1, not Cardano mainnet's 764824073: {AGAINST}"]),
    (cardano_ids(shelley=CARDANO_PREPROD_SHELLEY), [
        f"genesis IntentSettlement.CardanoIds holds Shelley genesis hash 0x{CARDANO_PREPROD_SHELLEY.hex()}, not "
        f"Cardano mainnet's 0x{CARDANO_MAINNET_SHELLEY.hex()}: {AGAINST}"]),
    (cardano_ids(aegis=bytes([0x5b]) * 28), [
        f"genesis IntentSettlement.CardanoIds binds aegis_policy_v1 script hash 0x{'5b' * 28}, not the "
        f"0x{AEGIS_POLICY.hex()} the launch declares deployed: every voucher the committee signs binds it"]),
    (cardano_ids(aegis=bytes(28)), [
        f"genesis IntentSettlement.CardanoIds binds no aegis_policy_v1 script hash, not the 0x{AEGIS_POLICY.hex()} the "
        "launch declares deployed: every voucher the committee signs binds it (a launch that binds it after genesis "
        "declares null)"]),
], ids=["preprod", "preprod-magic", "preprod-shelley", "another-aegis-policy", "no-aegis-policy"])
def test_a_genesis_settling_against_another_cardano_network_or_policy_is_refused(spec, stored, refusals):
    put(spec, "IntentSettlement", "CardanoIds", stored)
    assert messages(lp.check_settlement(spec, {"settlement": SETTLEMENT})) == [
        f"[11 settlement] {refusal}" for refusal in refusals]


def test_a_genesis_that_stores_no_cardano_network_is_refused(spec):
    assert messages(lp.check_settlement(spec, {"settlement": SETTLEMENT})) == [
        "[11 settlement] genesis stores no IntentSettlement.CardanoIds: settlement refuses every voucher, settlement "
        "and expiry"]


def test_a_launch_that_declares_no_aegis_policy_is_refused(spec):
    settles_on_mainnet(spec)
    assert messages(lp.check_settlement(spec, {})) == [
        "[11 settlement] the launch declares no settlement.aegis_policy_v1_script_hash: the Aegis policy deployed on "
        "Cardano mainnet that genesis binds, or null where Root binds it after genesis"]


@pytest.mark.parametrize("length", [63, 65])
def test_cardano_ids_of_another_width_are_unreadable(spec, length):
    put(spec, "IntentSettlement", "CardanoIds", cardano_ids()[:length].ljust(length, b"\0"))
    with pytest.raises(lp.InputError, match=f"IntentSettlement.CardanoIds is {length} bytes, not the 64"):
        lp.check_settlement(spec, {"settlement": SETTLEMENT})


@pytest.mark.parametrize("settlement", [
    [], {"aegis_policy_v1_script_hash": "0x" + AEGIS_POLICY.hex(), "network_magic": 1},
    {"aegis_policy_v1_script_hash": AEGIS_POLICY.hex()}, {"aegis_policy_v1_script_hash": "0x" + AEGIS_POLICY.hex().upper()},
    {"aegis_policy_v1_script_hash": "0x" + bytes(32).hex()}, {"aegis_policy_v1_script_hash": 7},
    {"aegis_policy_v1_script_hash": "0x" + bytes(28).hex()},
], ids=["list", "unknown-field", "no-0x", "upper-hex", "32-bytes", "number", "zero"])
def test_an_unreadable_settlement_declaration_is_an_input_error(spec, settlement):
    with pytest.raises(lp.InputError, match="settlement"):
        lp.validate_launch({**clean_manifest_fields(), "settlement": settlement})


def clean_manifest_fields() -> dict:
    return {"roles": {}, "supply": {"genesis_lock": LOCK}}


@pytest.mark.parametrize("settlement", [SETTLEMENT, BOUND_AFTER_GENESIS], ids=["in-genesis", "after-genesis"])
def test_a_launch_declares_the_aegis_policy_genesis_binds_or_null(settlement):
    lp.validate_launch({**clean_manifest_fields(), "settlement": settlement})


def test_genesis_may_store_settlements_cardano_network(spec, metadata_v14):
    """Rule 11 checks what the item holds; it holds no MATRA."""
    meta = lp.Metadata.from_v14(with_cardano_ids(metadata_v14))
    without = messages(lp.check_genesis_storage(spec, meta))
    settles_on_mainnet(spec)
    assert messages(lp.check_genesis_storage(spec, meta)) == without


# ---------------------------------------------------------------------------
# Rule 8: the genesis each authority's own node binary builds
# ---------------------------------------------------------------------------

# materios-node export-blocks, answering what the attestation asks: block 0 of the chain its --chain names, a raw
# spec file or a chain built into the node, written as export-blocks --binary writes it. It builds a file's genesis
# with the preflight's own computation, so these tests see the attestation's plumbing; test_node_attestation.py
# runs the real node. A --chain it cannot open as a file fails with the OS's error, as sc-chain-spec reports it. Its
# chain-id reports that genesis as settlement's and the oracle's chain ids, and the Cardano network settlement binds
# as the preflight reads it from the spec. KNOBS: tamper builds another state root, fail builds none from a file,
# built_in_refused none from a built-in chain, as the runtime refuses its genesis committee, preprod names the spec
# file whose genesis its built-in preprod builds, export writes other bytes, chain_ids reports other chain ids,
# no_chain_id has no chain-id subcommand, cardano_ids reports other Cardano ids, log records each call.
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
    manifest = chain_file and str(chain_file).startswith("mainnet:") and Path(str(chain_file)[len("mainnet:"):])
    with open(KNOBS["log"], "a") as log:
        log.write(json.dumps({"argv": sys.argv, "cwd": os.getcwd(), "cwd_files": os.listdir("."),
                              "env": dict(os.environ),
                              "registrations": registrations and Path(registrations).read_text(),
                              "chain_sha256": chain_file and chain_file.is_file()
                              and hashlib.sha256(chain_file.read_bytes()).hexdigest(),
                              "manifest_sha256": manifest and hashlib.sha256(manifest.read_bytes()).hexdigest()})
                  + "\\n")
if sys.argv[1] == "build-spec":
    chain = sys.argv[sys.argv.index("--chain") + 1]
    assert chain.startswith("mainnet:") and sys.argv[4:6] == ["--raw", "--disable-default-bootnode"], sys.argv
    json.loads(Path(chain[len("mainnet:"):]).read_text())
    if "refuses" in KNOBS:
        sys.exit('Error: Input("refusing the launch manifest: ' + KNOBS["refuses"] + '")')
    sys.stdout.write(KNOBS["prints"] if "prints" in KNOBS else Path(KNOBS["built"]).read_text())
    sys.exit(0)
if sys.argv[1] == "chain-id":
    if KNOBS.get("no_chain_id"):
        sys.exit("error: unrecognized subcommand 'chain-id'")
    genesis = lp.spec_genesis_hash(lp.load_spec(sys.argv[sys.argv.index("--chain") + 1]))
    ids = {"IntentSettlement.MateriosChainId": list(genesis), "Oracle.MateriosChainId": list(genesis),
           **KNOBS.get("chain_ids", {})}
    stored = lp.stored_cardano_ids(lp.load_spec(sys.argv[sys.argv.index("--chain") + 1]))
    cardano = stored and {"network_magic": stored[0], "mainchain_genesis_hash": list(stored[1]),
                          "aegis_policy_v1_script_hash": list(stored[2])}
    print(json.dumps({"genesis_hash": "0x" + genesis.hex(),
                      "constants": [[*constant.split("."), value] for constant, value in ids.items()],
                      "cardano_ids": KNOBS.get("cardano_ids", cardano)}))
    sys.exit(0)

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
built_in = chain in ("", "dev", "local", "preprod")
if built_in and KNOBS.get("built_in_refused"):
    sys.exit('Error: Service(Client(Storage("the genesis committee is empty, so its first rotation would '
             'schedule an empty GRANDPA set; list the authorities in sessionCommitteeManagement.'
             'initialAuthorities for blob:\\\\n{}")))')
if not built_in:
    try:
        os.close(os.open(chain, os.O_RDONLY))
    except OSError as e:
        sys.exit(f"Error: Input(\\"Error opening spec file `{chain}`: {e.strerror} (os error {e.errno})\\")")
source = KNOBS.get("preprod") if chain == "preprod" else None if built_in else chain
if source is None:
    root, version = lp.blake2_256(chain.encode()), 1
else:
    try:
        spec = lp.load_spec(source)
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
    """A stand-in for materios-node. Its build-spec prints the raw chain spec the file node-built-raw.json holds, the
    one the node builds from any launch manifest, unless the test has it refuse the manifest or print other text."""
    knobs.setdefault("built", str(tmp_path / "node-built-raw.json"))
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


NODE_PID = 4242


def process_stat(started_ticks: int = STARTED_TICKS, comm: str = "materios-node", pid: int = NODE_PID) -> str:
    """/proc/<pid>/stat: the pid, the command name in parentheses, then 50 fields, starttime the 20th after them."""
    fields = ["S", "1", *["0"] * 17, str(started_ticks), *["0"] * 30]
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def capture_block(settings: dict, pid: int = NODE_PID, started_ticks: int = STARTED_TICKS) -> bytes:
    """What the capture tool writes of a node process: the settings it keeps, in the order of their names, each
    NAME=value ended by a NUL, then the process they were read from, its pid and its start in ticks after boot."""
    return environ_block(dict(sorted(settings.items()))) + f"process={pid} {started_ticks}".encode() + b"\0"


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
            "when the node read it, and the node keeps the one it read. A directory's ctime also moves when an entry "
            "is added to it or removed, so keep the spec under directories nothing writes to once the node runs, and "
            "restart the node to take the path as it is now")


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


# A chain built into the node can fail to build here, as one whose genesis committee the runtime refuses does, and a
# node that fails is not one that read --chain as a file: only its own error for that missing file says it did.
@pytest.mark.parametrize("words, name", [(["--chain", "local"], "local"), (["--chain="], "")])
def test_a_node_that_fails_on_a_chain_name_without_missing_that_file_is_an_input_error(
        tmp_path, preprod_path, words, name):
    node = attested(tmp_path, preprod_path, argv=["materios-node", *words],
                    exe=fake_node(tmp_path, built_in_refused=True))
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: its node builds no genesis from --chain {name!r} here, and does not report it as a "
            "missing file: the preflight cannot tell whether the node reads it as a file or as a chain built into it "
            '(Error: Service(Client(Storage("the genesis committee is empty, so its first rotation would schedule '
            'an empty GRANDPA set')):
        node_findings(preprod_path, node)


# The red team's case, which the real-node suite runs on the node's own preprod: a chain built into the node whose
# genesis is the checked one is refused all the same.
def test_the_chain_built_into_the_node_as_preprod_is_refused_though_its_genesis_matches(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain=preprod"],
                    exe=fake_node(tmp_path, preprod=str(preprod_path)))
    assert node_findings(preprod_path, node) == [
        f"[8 node] authority val0: --chain 'preprod' builds genesis 0x{preprod_genesis_hex(preprod_path)} with no file "
        "of that name here: the node takes it as a chain built into it, not the checked chain spec"]


# A --chain through a file on this host, which the node fails to open, and not as a missing file.
def test_a_chain_path_through_a_file_on_this_host_is_an_input_error(tmp_path, preprod_path):
    (tmp_path / "raw.json").write_bytes(preprod_path.read_bytes())
    value = str(tmp_path / "raw.json" / "raw.json")
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", value])
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: its node builds no genesis from --chain {value!r} here, and does not report it as a "
            "missing file: the preflight cannot tell whether the node reads it as a file or as a chain built into it "
            f'(Error: Input("Error opening spec file `{value}`: Not a directory (os error 20)")')):
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
    assert [call["argv"][call["argv"].index("--chain") + 1] == str(here) for call in node_calls(log)
            if call["argv"][1] == "export-blocks"] == [True, False]


# The checked spec at the path its --chain names on this host, which the node builds no genesis from.
def test_a_node_that_builds_no_genesis_from_the_checked_spec_on_this_host_is_an_input_error(tmp_path, preprod_path):
    here = tmp_path / "here-raw.json"
    here.write_bytes(preprod_path.read_bytes())
    node = attested(tmp_path, preprod_path, argv=["materios-node", "--chain", str(here)],
                    exe=fake_node(tmp_path, fail=True))
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: its node builds no genesis from --chain {str(here)!r} on this host, where it is the "
            'checked chain spec: Error: Service(Other("the fake node builds no genesis"))')):
        node_findings(preprod_path, node)


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
    all_calls = node_calls(log)
    assert len(all_calls) == 3
    chain_id = next(call for call in all_calls if call["argv"][1] == "chain-id")
    assert set(chain_id["env"]) <= {"LC_CTYPE"}
    assert chain_id["argv"][1:3] == ["chain-id", "--chain"]
    assert len(chain_id["argv"]) == 4
    calls = [call for call in all_calls if call["argv"][1] == "export-blocks"]
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
    assert len(node_calls(log)) == 3


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
# Rule 8: the chain spec each authority's own node binary builds from the launch manifest
# ---------------------------------------------------------------------------

MANIFEST = b'{"the launch manifest": "as its file holds it,\\u0020byte for byte"}\n'


def raw_doc(spec: lp.Spec) -> dict:
    """A spec's document with its storage as its raw top."""
    return dict(spec.doc, genesis={"raw": {"top": {"0x" + key.hex(): "0x" + value.hex()
                                                   for key, value in spec.storage.items()}, "childrenDefault": {}}})


def pinned_to(exe: Path, name: str = "val0") -> dict:
    """An authority pinned to the node binary it runs."""
    return dict(authority(["materios-node", "--chain", "x"], name, name), exe=str(exe), exe_sha256=sha256_pin(exe))


@pytest.fixture
def built(mainnet, tmp_path):
    """The mainnet fixture, which the fake node builds from any manifest as the fixture stands now: a test edits
    the checked spec after."""
    spec, meta, _ = mainnet
    spec.doc = raw_doc(spec)
    (tmp_path / "node-built-raw.json").write_text(json.dumps(spec.doc))
    return spec, meta


def build_findings(spec, meta, *nodes, manifest: bytes = MANIFEST) -> list[str]:
    return messages(lp.check_node_build(spec, meta, {"nodes": list(nodes)}, manifest))


NOT_THE_BUILD = ("[8 node] authority val0: the checked chain spec is not the one its node binary builds from the "
                 "launch manifest: ")


def test_a_spec_that_is_its_nodes_build_of_the_launch_manifest_passes(built, tmp_path):
    """The pinned binary runs offline, once, on build-spec --chain mainnet:<manifest> --raw, in an empty directory,
    with no environment, on a base path of its own, and reads the manifest the check was given, byte for byte."""
    spec, meta = built
    log = tmp_path / "calls.jsonl"
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path, log=str(log)))) == []
    (call,) = node_calls(log)
    chain, base = call["argv"][3], call["argv"][7]
    assert call["argv"][1:] == ["build-spec", "--chain", chain, "--raw", "--disable-default-bootnode", "--base-path",
                                base]
    assert chain.startswith("mainnet:/") and call["manifest_sha256"] == hashlib.sha256(MANIFEST).hexdigest()
    assert set(call["env"]) <= {"LC_CTYPE"} and call["cwd_files"] == [] and base.startswith(call["cwd"] + "/")


def test_authorities_pinned_to_one_binary_share_its_build_and_another_binary_builds_again(built, tmp_path):
    spec, meta = built
    log = tmp_path / "calls.jsonl"
    one, other = fake_node(tmp_path, log=str(log)), fake_node(tmp_path, log=str(log), tamper=True)
    nodes = [pinned_to(one, "val0"), pinned_to(one, "val1"), pinned_to(other, "val2"), pinned_to(one, "val3")]
    assert build_findings(spec, meta, *nodes) == []
    assert len(node_calls(log)) == 2


def test_a_binary_that_is_not_the_pinned_one_and_a_node_that_is_no_authority_are_not_run(built, tmp_path):
    spec, meta = built
    log = tmp_path / "calls.jsonl"
    exe = fake_node(tmp_path, log=str(log))
    unpinned = dict(pinned_to(exe), exe_sha256="0x" + hashlib.sha256(b"the release binary").hexdigest())
    edge = {"name": "edge", "host": "edge", "authority": False}
    assert build_findings(spec, meta, unpinned, edge) == []
    assert node_calls(log) == []


def test_a_node_that_refuses_the_launch_manifest_builds_no_such_spec(built, tmp_path):
    spec, meta = built
    refusal = "dust.oracle endows an account the builder sizes no dust for"
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path, refuses=refusal))) == [
        "[8 node] authority val0: its node binary builds no mainnet chain spec from the launch manifest "
        f'(Error: Input("refusing the launch manifest: {refusal}")): the checked chain spec is not one the node '
        "builds from it"]


@pytest.mark.parametrize("printed", ["", "not JSON", "[]", '{"genesis": {"raw": {}}}',
                                     '{"genesis": {"raw": {"top": []}}}',
                                     '{"name": 1, "name": 2, "genesis": {"raw": {"top": {}}}}'],
                         ids=["nothing", "not JSON", "a list", "no top", "top a list", "a key twice"])
def test_a_build_spec_that_prints_no_raw_chain_spec_is_an_input_error(built, tmp_path, printed):
    spec, meta = built
    with pytest.raises(lp.InputError, match="^authority val0: its node's build-spec printed no raw chain spec: "):
        build_findings(spec, meta, pinned_to(fake_node(tmp_path, prints=printed)))


def account_entry(account: bytes) -> str:
    return f"System.Account[0x{account_key(account)[32:].hex()}]"


def set_code(spec: lp.Spec) -> str:
    spec.storage[lp.CODE_KEY] = b"another runtime"
    return (f"genesis :code (blake2-256 {lp.blake2_256(b'another runtime').hex()}) is not the runtime its node binary "
            f"embeds and builds mainnet with ({lp.blake2_256(b'').hex()})")


def no_code(spec: lp.Spec) -> str:
    del spec.storage[lp.CODE_KEY]
    return ("genesis :code (blake2-256 none) is not the runtime its node binary embeds and builds mainnet with "
            f"({lp.blake2_256(b'').hex()})")


def unset(pallet: str, item: str):
    def edit(spec: lp.Spec) -> str:
        del spec.storage[lp.storage_key(pallet, item)]
        return f"genesis storage differs at 1 key: {pallet}.{item}, which only the node's build sets"
    return edit


def under_sudo(spec: lp.Spec) -> str:
    spec.storage[lp.storage_key("Sudo", "Key") + b"\x01"] = bytes(32)
    return "genesis storage differs at 1 key: Sudo.Key[0x01], which only the checked spec sets"


def frozen_treasury(spec: lp.Spec) -> str:
    spec.storage[account_key(TREASURY)] = account_info(ED, frozen=1)
    return f"genesis storage differs at 1 key: {account_entry(TREASURY)}, whose value differs"


def three_kinds(spec: lp.Spec) -> str:
    put(spec, "Motra", "Params", bytes(108))
    del spec.storage[b":extrinsic_index"]
    spec.storage[lp.twox_128(b"Balances") + lp.twox_128(b":__STORAGE_VERSION__:")] = bytes(2)
    spec.storage[bytes([255]) * 40] = b"\x01"
    spec.storage[b":heappages"] = bytes(8)
    return ("genesis storage differs at 5 keys: :extrinsic_index, which only the node's build sets; :heappages, which "
            "only the checked spec sets; the storage version of Balances, whose value differs; Motra.Params, whose "
            f"value differs; storage 0x{'ff' * 40}, which only the checked spec sets")


def twenty_accounts(spec: lp.Spec) -> str:
    accounts = spec.accounts()[:20]
    for account in accounts:
        del spec.storage[account_key(account)]
    named = "; ".join(f"{account_entry(account)}, which only the node's build sets" for account in accounts[:16])
    return f"genesis storage differs at 20 keys: {named}; and 4 more"


STORAGE_APART = [set_code, no_code, unset("Grandpa", "CurrentSetId"), unset("PalletSession", "Validators"),
                 unset("System", "LastRuntimeUpgrade"), under_sudo, frozen_treasury, three_kinds, twenty_accounts]


@pytest.mark.parametrize("edit", STORAGE_APART, ids=["another code", "no code", "no set id", "no session validators",
                                                    "no last upgrade", "a key under Sudo.Key", "a frozen Treasury",
                                                    "set, unset and changed", "twenty accounts"])
def test_genesis_storage_the_node_does_not_build_is_refused_naming_each_key(built, tmp_path, edit):
    spec, meta = built
    difference = edit(spec)
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == [NOT_THE_BUILD + difference]


FORK_BLOCK = [[1, "0x" + "ab" * 32]]
BOOT_NODE = "/dns/boot.example/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"
FIELDS_APART = [
    ("codeSubstitutes", {"1": "0x00"}, 'its codeSubstitutes is {"1": "0x00"}, where the node\'s build gives {}'),
    ("name", "Materios ", 'its name is "Materios ", where the node\'s build gives "Materios"'),
    ("id", "materios", 'its id is "materios", where the node\'s build gives "materios_mainnet"'),
    ("chainType", "Local", 'its chainType is "Local", where the node\'s build gives "Live"'),
    ("protocolId", None, 'its protocolId is null, where the node\'s build gives "materios"'),
    ("properties", {"ss58Format": 42, "tokenDecimals": 12, "tokenSymbol": "MATRA"},
     'its properties is {"ss58Format": 42, "tokenDecimals": 12, "tokenSymbol": "MATRA"}, where the node\'s build '
     'gives {"ss58Format": 42, "tokenDecimals": 6, "tokenSymbol": "MATRA"}'),
    ("telemetryEndpoints", [["wss://telemetry.example/submit", 0]],
     'its telemetryEndpoints is [["wss://telemetry.example/submit", 0]], where the node\'s build gives null'),
] + [(field, value, f"it gives {field}, which the node's build does not: the node reads a code substitute, a fork "
                    "id, a fork or bad block and other fields a build never writes")
     for field, value in (("forkBlocks", FORK_BLOCK), ("badBlocks", ["0x" + "ab" * 32]), ("forkId", "fork"),
                          ("lightSyncState", {}), ("consensusEngine", None), ("anything", 1))]


@pytest.mark.parametrize("field, value, difference", FIELDS_APART, ids=[field for field, _, _ in FIELDS_APART])
def test_a_chain_spec_field_the_node_does_not_build_is_refused(built, tmp_path, field, value, difference):
    spec, meta = built
    spec.doc[field] = value
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == [NOT_THE_BUILD + difference]


def test_a_chain_spec_without_a_field_the_node_builds_is_refused(built, tmp_path):
    spec, meta = built
    del spec.doc["codeSubstitutes"]
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == [
        NOT_THE_BUILD + "it has no codeSubstitutes, which the node's build gives as {}"]


@pytest.mark.parametrize("edit", [
    lambda doc: doc["genesis"]["raw"].pop("childrenDefault"),
    lambda doc: doc["genesis"]["raw"].update(childrenDefault={"0x00": {"0x01": "0x02"}}),
    lambda doc: doc["genesis"]["raw"].update(extra=1),
    lambda doc: doc["genesis"].update(runtimeGenesis={"patch": {}}),
], ids=["no child storage", "child storage", "another raw field", "another genesis field"])
def test_a_genesis_that_holds_other_than_the_top_storage_the_node_builds_is_refused(built, tmp_path, edit):
    spec, meta = built
    edit(spec.doc)
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == [
        NOT_THE_BUILD + "its genesis holds other than the top storage and the empty child storage the node's build "
                        "holds"]


def test_the_boot_nodes_are_the_operators_to_give(built, tmp_path):
    spec, meta = built
    spec.doc["bootNodes"] = [BOOT_NODE]
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == []
    del spec.doc["bootNodes"]
    assert build_findings(spec, meta, pinned_to(fake_node(tmp_path))) == []


def test_a_storage_key_is_named_by_what_the_metadata_declares(mainnet):
    _, meta, _ = mainnet
    sudo, version = lp.storage_key("Sudo", "Key"), lp.twox_128(b"Motra") + lp.twox_128(b":__STORAGE_VERSION__:")
    assert [meta.entry(key) for key in (b":code", b":heappages", sudo, sudo + b"\x07", version, bytes(32),
                                        account_key(TREASURY))] == [
        ":code", ":heappages", "Sudo.Key", "Sudo.Key[0x07]", "the storage version of Motra", f"storage 0x{'00' * 32}",
        account_entry(TREASURY)]


# ---------------------------------------------------------------------------
# End to end through the CLI, with the real subwasm
# ---------------------------------------------------------------------------

def subwasm() -> str:
    path = os.environ.get("SUBWASM") or shutil.which("subwasm")
    assert path, "set SUBWASM or put subwasm on PATH: the CLI tests run the real extractor"
    return path


# What an authority may set that the capture of its node's environment leaves out.
LOGGING = {"RUST_LOG", "RUST_BACKTRACE", "RUST_LIB_BACKTRACE", "TZ"}


class Launch:
    """A clean launch: the mainnet genesis the node builds from fixtures/mainnet-launch.json, its fixed issuance of
    dust and its attestation committee among it, with the preprod v6 runtime as its code and the LastRuntimeUpgrade
    build-spec writes for that code; Root and its timelock guardian moved to multisigs of fresh keys whose holders
    the tests sign as, and settlement bound to an Aegis policy deployed on Cardano mainnet; Cardano holding the lock
    and the authorities as the candidates, in outputs older than two epochs; a public RPC URL that serves only safe
    methods, and authorities that load the spec from its own file, pinned to a node binary that builds the genesis
    the preflight computes. Every rule accepts it."""

    def __init__(self, preprod_path, tmp_path, kupo, endpoint):
        spec = lp.load_spec(str(FIXTURES / "mainnet-launch-raw.json"))
        preprod = lp.load_spec(str(preprod_path))
        spec.storage[lp.CODE_KEY] = preprod.code
        put(spec, "System", "LastRuntimeUpgrade", preprod.value("System", "LastRuntimeUpgrade"))
        launch = json.loads((FIXTURES / "mainnet-launch.json").read_text())
        held = {}
        for role in ("sudo", "guardian"):
            entry = launch["roles"][role][0]
            fresh = [fresh_account() for _ in entry["members"]]
            for member, key in zip(entry["members"], fresh):
                held[member["key"]] = key
            launch["roles"][role] = [msig(entry["threshold"], *fresh)]
        old_sudo = ss58(spec.value("Sudo", "Key"))
        self.sudo_members = [lp.decode_public_key(member) for member in launch["roles"]["sudo"][0]["members"]]
        sudo = lp.multisig_account(self.sudo_members, 2)
        held[old_sudo] = sudo
        for old, new in held.items():
            move_account(spec, lp.decode_public_key(old), new)
        put(spec, "Sudo", "Key", sudo)
        put(spec, "RootTimelock", "Guardian", lp.role_account(launch["roles"]["guardian"][0]))
        launch["roles"]["endowed"] = [ss58(held[name]) for name in launch["roles"]["endowed"]]
        launch["dust"] = {role: {ss58(held[name]) if name in held else name: amount for name, amount in accounts.items()}
                          for role, accounts in launch["dust"].items()}
        settles_on_mainnet(spec)
        self.attestor = lp.decode_public_key(launch["roles"]["attestors"][0])
        self.members = lp.genesis_committee(spec)[1]
        self.spec = spec
        self.tmp_path, self.kupo = tmp_path, kupo
        conf = tmp_path / "rpc.conf"
        conf.write_text("location / { proxy_pass http://rpc-node:9944; }")
        self.launch = dict(
            launch, supply={"genesis_lock": LOCK}, settlement=dict(SETTLEMENT),
            nodes=[{"name": "edge", "host": "edge", "authority": False}],
            rpc_proxies=[{"name": "public-rpc", "node": "edge", "kind": "nginx", "config": str(conf),
                          "other_targets": ["rpc-node:9944"]}],
            public_rpc=[endpoint.url])
        self.endpoint = endpoint
        self.lock_output = kupo_output(assets={lp.CMATRA_UNIT: lp.MATRA})
        # None serves this genesis hash as the lock's inline datum.
        self.lock_datum = None
        self.node_exe = fake_node(tmp_path)
        self.launch["nodes"][:0] = [self.authority(f"val{i}", aura, gran, cross_chain)
                                    for i, (cross_chain, aura, gran) in enumerate(self.members)]
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
        # The raw chain spec the node binary builds from the launch manifest, where a test gives other than the
        # checked spec.
        self.built = None
        # The settings each authority's node process was started with, where a test gives other than its manifest
        # declares.
        self.environ = {}
        self.launch_key = signing.SigningKey.generate()
        self.candidates = legacy_datum(self.members)
        self.d_parameter = d_parameter_datum(len(self.members))

    def hold(self, role: str, entry) -> None:
        """Hand roles.<role>, sudo or guardian, to `entry`: genesis names its account as Sudo.Key or the timelock
        guardian, the sudo account keeps its dust, and the old entry's keyholders give way to the new one's. Each new
        keyholder a test can sign as, and each nested multisig, holds a keyholder's dust, declared under endowed."""
        item = {"sudo": ("Sudo", "Key"), "guardian": ("RootTimelock", "Guardian")}[role]
        old, account = self.launch["roles"][role][0], lp.role_account(entry)
        if role == "sudo":
            dust = self.launch["dust"]["sudo"]
            dust[ss58(account)] = dust.pop(ss58(self.spec.value(*item)))
            move_account(self.spec, self.spec.value(*item), account)
        put(self.spec, *item, account)
        for _, keyholder in list(lp.role_accounts(old, ""))[1:]:
            if ss58(keyholder) in self.launch["roles"]["endowed"]:
                drop_account(self.spec, keyholder)
                del self.launch["dust"]["endowed"][ss58(keyholder)]
                self.launch["roles"]["endowed"].remove(ss58(keyholder))
        nested = {path for path, _ in lp.role_multisigs(entry, "")}
        keys = {where: lp.key_text(leaf) for where, _, leaf in lp.role_leaves(entry, "")}
        for where, keyholder in list(lp.role_accounts(entry, ""))[1:]:
            seated = where in nested or (where in keys and held(keys[where]) is not None)
            if seated and ss58(keyholder) not in self.launch["roles"]["endowed"]:
                set_account(self.spec, keyholder, KEYHOLDER_DUST[role])
                self.launch["dust"]["endowed"][ss58(keyholder)] = KEYHOLDER_DUST[role]
                self.launch["roles"]["endowed"].append(ss58(keyholder))
        self.launch["roles"][role] = [entry]

    def authority(self, name: str, aura: bytes, grandpa: bytes, cross_chain: bytes) -> dict:
        """An authority that runs the fake node, pinned to it, on the spec from its own file."""
        node = authority(["materios-node", "--validator", "--chain", authority_chain(self.tmp_path), "--rpc-methods",
                          "safe"], name, name, aura, cross_chain)
        return dict(node, grandpa="0x" + grandpa.hex(), env=dict(AUTHORITY_ENV),
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

    def node_builds_this(self) -> None:
        """The node binary builds the spec as it stands now, whatever the test makes of the checked spec after."""
        self.built = self.spec_path().read_text()

    def prepare(self) -> Path:
        """Write each authority's captures and the spec, serve Cardano for that spec, and return its path."""
        for node in self.launch["nodes"]:
            if node["authority"] and isinstance(node.get("argv"), list) and "cmdline" in node:
                capture(self.tmp_path, node["name"], self.running.get(node["name"], node["argv"]))
                declared = {name: value for name, value in node.get("env", {}).items() if name not in LOGGING}
                Path(node["cmdline"] + ".environ").write_bytes(
                    capture_block(self.environ.get(node["name"], declared)))
        spec_path = self.spec_path()
        (self.tmp_path / "node-built-raw.json").write_text(spec_path.read_text() if self.built is None else self.built)
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
        """`sign`, then `check`, with each multisig member's holder's proof of possession collected first."""
        spec_path = self.prepare()
        return run_cli(self.tmp_path, spec_path, prove(self.launch, lp.load_spec(str(spec_path))), capsys,
                       self.kupo.url, key or self.launch_key, manifest_key, extra, signed_launch)

    def run_respelled(self, capsys, respell) -> tuple[int, int, str]:
        """`sign`, then `check`, on this launch's spec with its raw storage then rewritten by `respell`."""
        spec_path = self.prepare()
        doc = json.loads(spec_path.read_text())
        respell(doc["genesis"]["raw"]["top"])
        spec_path.write_text(json.dumps(doc))
        return sign_and_check(self.tmp_path, spec_path, self.launch, capsys, self.kupo.url, self.launch_key)


def no_provider(role: str, index: int, key: bytes) -> str:
    """Rule 12 on a keyholder of the clean launch's sudo or guardian multisig that genesis does not endow."""
    return (f"[12 dust] roles.{role}[0].members[{index}], a keyholder of roles.{role}[0] ({ss58(key)}) has no provider "
            "at genesis: it cannot sign, and nothing after genesis endows it")


# What the clean launch endows a keyholder it seats, by the role it holds: above the floor of a keyholder of
# multisigs whose thresholds take up to 6,000 in deposits, with the working dust of its role's calls left free,
# 13,847 for the guardian's veto within ten blocks and 10,806 for Root's calls and an upgrade of twice the clean
# launch's runtime.
KEYHOLDER_DUST = {"sudo": 30_000, "guardian": 20_000}


def drop_account(spec: lp.Spec, account: bytes) -> None:
    """Take an account out of genesis, its System.Account and its Motra.AccrualCheckpoint, and its balance out of the
    issuance and the fixed issuance."""
    set_account(spec, account, 0)
    for pallet, item in (("System", "Account"), ("Motra", "AccrualCheckpoint")):
        spec.storage.pop(lp.storage_key(pallet, item) + hashlib.blake2b(account, digest_size=16).digest() + account,
                         None)


def move_account(spec: lp.Spec, old: bytes, new: bytes) -> None:
    """Give an account's genesis entries, its System.Account and its Motra.AccrualCheckpoint, to another account."""
    for pallet, item in (("System", "Account"), ("Motra", "AccrualCheckpoint")):
        prefix = lp.storage_key(pallet, item)
        spec.storage[prefix + hashlib.blake2b(new, digest_size=16).digest() + new] = spec.storage.pop(
            prefix + hashlib.blake2b(old, digest_size=16).digest() + old)


def pin_launch_keys(monkeypatch, tmp_path, *keys: bytes) -> None:
    path = tmp_path / "launch_keys.json"
    path.write_text(json.dumps({"keys": ["0x" + key.hex() for key in keys]}))
    monkeypatch.setattr(lp, "LAUNCH_KEYS", path)


def sign_and_check(tmp_path, spec_path: Path, launch: dict, capsys, kupo_url: str, key=None, manifest_key=None,
                   extra=(), signed_launch=None) -> tuple[int, int, str]:
    """Sign with `key`, then check against the pinned launch keys, or against
    `manifest_key` given on the command line, with the operator's key tables
    `extra` gives or else an empty one. Returns both exit codes and what the
    check printed."""
    if "--extra-well-known" not in extra:
        operator = tmp_path / "operator-keys.json"
        operator.write_text(json.dumps({"keys": []}))
        extra = (*extra, "--extra-well-known", str(operator))
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


@pytest.fixture
def clean(preprod_path, tmp_path, kupo, endpoint, monkeypatch):
    """The spec's code is the preprod v6 runtime, which is not the spec 244 runtime that built the genesis, so the
    extractor returns spec 244's metadata."""
    v14 = json.loads((FIXTURES / "spec244-metadata.json").read_text())["V14"]
    monkeypatch.setattr(lp, "subwasm_metadata", lambda code, subwasm: v14)
    launch = Launch(preprod_path, tmp_path, kupo, endpoint)
    pin_launch_keys(monkeypatch, tmp_path, pub(launch.launch_key))
    return launch


def test_cli_refuses_the_preprod_spec_naming_the_dev_anchor_signer(preprod_path, tmp_path, capsys, kupo):
    spec = lp.load_spec(str(preprod_path))
    kupo.serve(spec, kupo_output(assets={lp.CMATRA_UNIT: 975_000 * MATRA}), genesis_candidates_datum(spec))
    launch = {"roles": {"anchor_signer": [ss58(ALICE)], "attestors": [ss58(PREPROD_ATTESTOR)], "oracle": [],
                        "sudo": [ss58(fresh_account())]},
              "economics": dict(TUNED), "supply": {"genesis_lock": LOCK},
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
    assert "[4 supply] genesis sets no OrinqReceipts.FixedIssuance" in out
    assert "base units, at least one MATRA (1000000)" in out
    assert NO_GUARDIAN in out
    assert HIDDEN_BOUNDS in out


def test_cli_passes_a_clean_launch(clean, capsys):
    code, out = clean.run(capsys)
    assert out.splitlines()[0] == "MAINNET LAUNCH PREFLIGHT: PASS"
    assert code == 0


def test_cli_gives_each_pinned_node_binary_the_launch_manifest_it_was_given(clean, capsys):
    log = clean.tmp_path / "calls.jsonl"
    exe = fake_node(clean.tmp_path, log=str(log))
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node.update(exe=str(exe), exe_sha256=sha256_pin(exe))
    code, out = clean.run(capsys)
    assert code == 0, out
    builds = [call for call in node_calls(log) if call["argv"][1] == "build-spec"]
    assert [call["manifest_sha256"] for call in builds] == [
        hashlib.sha256((clean.tmp_path / "launch.json").read_bytes()).hexdigest()]


def only_reason(out: str, reason: str) -> bool:
    return out == f"MAINNET LAUNCH PREFLIGHT: REFUSE (1 reasons)\n  {reason}\n"


# Storage no rule but the node's own build holds to a value: a GRANDPA set id, session validators and a last runtime
# upgrade that genesis leaves unset read as the values build-spec writes.
@pytest.mark.parametrize("pallet, item", [("Grandpa", "CurrentSetId"), ("PalletSession", "Validators"),
                                          ("PalletSession", "QueuedKeys"), ("System", "LastRuntimeUpgrade")])
def test_cli_refuses_genesis_storage_the_pinned_node_does_not_build(clean, capsys, pallet, item):
    clean.node_builds_this()
    del clean.spec.storage[lp.storage_key(pallet, item)]
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(out, f"{NOT_THE_BUILD}genesis storage differs at 1 key: {pallet}.{item}, which "
                                          "only the node's build sets"), out


@pytest.mark.parametrize("field, value", [("forkBlocks", FORK_BLOCK), ("badBlocks", ["0x" + "ab" * 32]),
                                          ("forkId", "fork")])
def test_cli_refuses_a_chain_spec_field_the_pinned_node_does_not_build(clean, capsys, field, value):
    clean.node_builds_this()
    clean.spec.doc[field] = value
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(out, f"{NOT_THE_BUILD}it gives {field}, which the node's build does not: the "
                                          "node reads a code substitute, a fork id, a fork or bad block and other "
                                          "fields a build never writes"), out


def test_cli_refuses_a_runtime_the_pinned_node_does_not_embed(clean, capsys):
    """The node builds mainnet with the runtime it embeds: a spec that carries another, here one more custom section
    after the same code, is no build of it."""
    clean.node_builds_this()
    code = lp.decompressed_code(clean.spec.code) + custom_section(b"note", b"another build")
    clean.spec.storage[lp.CODE_KEY] = code
    exit_code, out = clean.run(capsys)
    assert exit_code == 1 and f"{NOT_THE_BUILD}genesis :code (blake2-256 {lp.blake2_256(code).hex()}) is not the " \
        "runtime its node binary embeds and builds mainnet with (" in out, out


def test_cli_refuses_a_launch_manifest_the_pinned_node_builds_nothing_from(clean, capsys):
    exe = fake_node(clean.tmp_path, refuses="roles.oracle names 1 oracles")
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node.update(exe=str(exe), exe_sha256=sha256_pin(exe))
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(
        out, "[8 node] authority val0: its node binary builds no mainnet chain spec from the launch manifest (Error: "
             'Input("refusing the launch manifest: roles.oracle names 1 oracles")): the checked chain spec is not one '
             "the node builds from it"), out


def test_cli_passes_a_spec_that_differs_from_the_pinned_nodes_build_in_its_boot_nodes_alone(clean, capsys):
    clean.node_builds_this()
    clean.spec.doc["bootNodes"] = [BOOT_NODE]
    code, out = clean.run(capsys)
    assert code == 0, out


def keyholders(clean) -> list[bytes]:
    return [lp.role_account(member) for role in ("sudo", "guardian")
            for member in clean.launch["roles"][role][0]["members"]]


def reshape(clean, accounts, **fields) -> None:
    for account in accounts:
        clean.spec.storage[account_key(account)] = account_info(clean.spec.balance(account)[0], **fields)


def frozen_keyholders(clean) -> list[str]:
    """Every sudo and guardian keyholder and rescuer with its whole balance frozen: none can reserve the deposit of
    a multisig call or a recovery, so Root, its veto and its recovery are held by no one."""
    reshape(clean, keyholders(clean) + [lp.role_account(entry) for entry in clean.launch["roles"]["recovery_rescuers"]],
            frozen=2**128 - 1)
    return [f"[4 supply] genesis System.Account of {ss58(account)} holds nonce 0, consumers 0, providers 1, "
            f"sufficients 0, frozen {2**128 - 1} and flags 0x80000000000000000000000000000000, not the nonce 0"
            for account in keyholders(clean)]


def used_keyholders(clean) -> list[str]:
    reshape(clean, keyholders(clean), nonce=2**32 - 1, consumers=3, sufficients=9, providers=7, flags=0)
    return [f"[4 supply] genesis System.Account of {ss58(account)} holds nonce 4294967295, consumers 3, providers 7, "
            "sufficients 9, frozen 0 and flags 0x00000000000000000000000000000000, not the nonce 0"
            for account in keyholders(clean)]


def committee_past_its_bound(clean) -> list[str]:
    members = lp.fixed_list(clean.spec.value("OrinqReceipts", "CommitteeMembers"), 32, "the clean committee")
    listed = members + [members[0]] * (97 - len(members))
    put(clean.spec, "OrinqReceipts", "CommitteeMembers", lp.compact(97) + b"".join(listed))
    return [not_a_set(97, 3), "[1 dev-keys] genesis OrinqReceipts.CommitteeMembers lists 97 attestors, and the "
                              "runtime's OrinqReceipts.MaxCommitteeSize is 96"]


def motra_params_of_ones(clean) -> list[str]:
    put(clean.spec, "Motra", "Params", bytes([255]) * 108)
    return [f"[12 dust] genesis stores Motra.Params with min_fee {2**128 - 1} for 1000000000, congestion_rate"]


def no_motra_params(clean) -> list[str]:
    del clean.spec.storage[lp.storage_key("Motra", "Params")]
    return [f"[12 dust] genesis sets no Motra.Params, which the runtime reads as all zero: {MOTRA_SIZED_FOR}"]


def checkpoints(clean) -> list[bytes]:
    return [key for key in clean.spec.storage if key.startswith(lp.storage_key("Motra", "AccrualCheckpoint"))]


def no_checkpoints(clean) -> list[str]:
    for key in checkpoints(clean):
        del clean.spec.storage[key]
    return [f"[12 dust] genesis sets no Motra.AccrualCheckpoint for {ss58(account)}, not the "
            f"{clean.spec.balance(account)[0]} it holds free" for account in clean.spec.accounts()]


def empty_checkpoints(clean) -> list[str]:
    for key in checkpoints(clean):
        clean.spec.storage[key] = bytes(20)
    return [f"[12 dust] genesis checkpoints 0 MATRA base units held since block 0 for {ss58(account)}, not the "
            f"{clean.spec.balance(account)[0]} it holds free" for account in clean.spec.accounts()]


def backup_signers(clean) -> list[str]:
    put(clean.spec, "OrinqReceipts", "BackupSigners", clean.spec.value("OrinqReceipts", "CommitteeMembers"))
    put(clean.spec, "OrinqReceipts", "BackupSignerDelay", (2**31).to_bytes(4, "little"))
    return [f"[4 supply] genesis sets OrinqReceipts.{item} (1 entry), which a mainnet genesis may not set"
            for item in ("BackupSignerDelay", "BackupSigners")]


def no_receipt_expiry(clean) -> list[str]:
    put(clean.spec, "OrinqReceipts", "ReceiptExpiryBlocks", bytes(4))
    return ["[2 rewards] genesis stores 0x00000000 as OrinqReceipts.ReceiptExpiryBlocks, not the 0x40380000 "
            "build-spec writes"]


def key_under_sudo(clean) -> list[str]:
    key = lp.storage_key("Sudo", "Key") + b"\x01"
    clean.spec.storage[key] = bytes([17]) * 32
    return [f"[4 supply] genesis sets storage 0x{key.hex()}, a key under Sudo.Key's that the runtime does not read, "
            "(1 entry)"]


def balances_at_version_0(clean) -> list[str]:
    clean.spec.storage[lp.twox_128(b"Balances") + lp.twox_128(b":__STORAGE_VERSION__:")] = bytes(2)
    return ["[4 supply] genesis stores 0x0000 as the storage version of Balances, not the 0x0100 build-spec writes"]


def no_settlement_signer(clean) -> list[str]:
    put(clean.spec, "IntentSettlement", "MinSignerThreshold", bytes(4))
    return ["[11 settlement] genesis stores 0x00000000 as IntentSettlement.MinSignerThreshold, not the 0x01000000 "
            "build-spec writes"]


NO_NODES_BUILD = [frozen_keyholders, used_keyholders, committee_past_its_bound, motra_params_of_ones, no_motra_params,
                  no_checkpoints, empty_checkpoints, backup_signers, no_receipt_expiry, key_under_sudo,
                  balances_at_version_0, no_settlement_signer]


# Raw specs no build-spec writes, each of which the rules that read the spec apart from the node's builder refuse
# by themselves: the fake node here builds whatever spec is checked.
@pytest.mark.parametrize("edit", NO_NODES_BUILD, ids=[edit.__name__ for edit in NO_NODES_BUILD])
def test_cli_refuses_a_raw_spec_no_build_spec_writes(clean, capsys, edit):
    reasons = edit(clean)
    code, out = clean.run(capsys)
    assert code == 1, out
    assert [reason for reason in reasons if f"\n  {reason}" not in out] == [], out
    assert "[8 node]" not in out


def test_cli_refuses_such_a_spec_by_the_pinned_nodes_build_too(clean, capsys):
    clean.node_builds_this()
    reasons = frozen_keyholders(clean)
    code, out = clean.run(capsys)
    assert code == 1 and all(f"\n  {reason}" in out for reason in reasons), out
    assert f"\n  {NOT_THE_BUILD}genesis storage differs at {len(reasons) + 1} keys: System.Account[0x" in out, out


def test_cli_refuses_a_launch_whose_genesis_settles_against_cardano_preprod(clean, capsys):
    put(clean.spec, "IntentSettlement", "CardanoIds", cardano_ids(1, CARDANO_PREPROD_SHELLEY, bytes(28)))
    code, out = clean.run(capsys)
    assert code == 1, out
    assert "[11 settlement] genesis IntentSettlement.CardanoIds holds network magic 1" in out
    assert "[11 settlement] genesis IntentSettlement.CardanoIds holds Shelley genesis hash 0x162d29c4" in out
    assert "[11 settlement] genesis IntentSettlement.CardanoIds binds no aegis_policy_v1 script hash" in out


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
    clean.candidates = legacy_datum([(cross_chain_key(), aura, outsider if i == 0 else gran)
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
    "a space after 0x": (respell_timelock(MISSPELLINGS["a space after 0x"]),
                         (f"value at {GUARDIAN_KEY}", f"value at {DELAYS_KEY}")),
    "no 0x and a leading byte": (respell_timelock(MISSPELLINGS["no 0x and a leading byte"]),
                                 (f"value at {GUARDIAN_KEY}", f"value at {DELAYS_KEY}")),
    "spaces after the guardian key": (lambda top: top.update({GUARDIAN_KEY + "  ": top.pop(GUARDIAN_KEY)}),
                                      (f"key '{GUARDIAN_KEY}  '",)),
}


@pytest.mark.parametrize("respell, entries", TIMELOCK_EXPLOITS.values(), ids=TIMELOCK_EXPLOITS.keys())
def test_cli_refuses_a_timelock_the_node_would_load_as_other_bytes(clean, capsys, respell, entries):
    """The preflight refuses the first respelt value it reads, of either item."""
    signing_code, code, out = clean.run_respelled(capsys, respell)
    assert (signing_code, code) == (2, 2), out
    assert any(f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) chain spec raw storage {entry} {MISSPELLED}" in out
               for entry in entries), out


def test_cli_refuses_a_balance_the_node_would_load_4096_times_larger(clean, capsys):
    """The red team's rule 4 exploit: a space after 0x shifts every nibble of an
    account's balance, which the preflight read as within the lock."""
    extra = fresh_account()
    endow(clean.spec, extra, int.from_bytes(bytes([0x0F] * 9), "little"))
    clean.launch["roles"]["endowed"].append(ss58(extra))
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


def test_cli_refuses_a_guardian_one_keyholder_runs_through_a_nested_multisig(clean, capsys):
    entry, [(key, paths)] = repeated_member()
    clean.hold("guardian", entry)
    code, out = clean.run(capsys)
    assert code == 1
    assert lone_holder("7 timelock", "roles.guardian[0]", key, paths, GUARDIAN_POWER) in out


def test_cli_refuses_root_one_keyholder_runs_through_a_nested_multisig(clean, capsys):
    entry, [(key, paths)] = repeated_member()
    clean.hold("sudo", entry)
    code, out = clean.run(capsys)
    assert code == 1
    assert lone_holder("1 dev-keys", "roles.sudo[0]", key, paths, SUDO_POWER) in out


@pytest.mark.parametrize("count, code", [(10, 0), (11, 1)])
def test_cli_bounds_the_guardian_by_the_runtime_max_signatories(clean, capsys, count, code):
    """Each guardian keyholder holds the dust of a veto within ten blocks, and ten of them leave the fixture's other
    dust no room under one MATRA: the sudo keyholders give up what they hold above the clean launch's floor."""
    for keyholder in clean.sudo_members:
        redust(clean.spec, clean.launch, "endowed", ss58(keyholder), KEYHOLDER_DUST["sudo"])
    clean.hold("guardian", msig(2, *(fresh_account() for _ in range(count))))
    exit_code, out = clean.run(capsys)
    assert exit_code == code, out
    assert (too_many_signatories("7 timelock", "roles.guardian[0]", count) in out) == (code == 1)


@pytest.mark.parametrize("threshold", [1, 2])
def test_cli_refuses_root_held_by_a_multisig_with_a_dev_member(clean, capsys, threshold):
    members = [ALICE, *clean.sudo_members[:2]]
    clean.hold("sudo", msig(threshold, *members))
    code, out = clean.run(capsys)
    assert code == 1
    assert "[1 dev-keys] roles.sudo[0].members[0]: //Alice (sr25519)" in out


def test_cli_refuses_root_declared_by_its_flat_address(clean, capsys):
    hidden = lp.multisig_account([ALICE, *clean.sudo_members[:2]], 1)
    clean.hold("sudo", ss58(hidden))
    code, out = clean.run(capsys)
    assert code == 1
    assert SUDO_FLAT in out


def test_cli_refuses_root_held_by_an_undeclared_multisig(clean, capsys):
    hidden = lp.multisig_account([ALICE, *clean.sudo_members[:2]], 2)
    put(clean.spec, "Sudo", "Key", hidden)
    code, out = clean.run(capsys)
    assert code == 1
    assert f"[1 dev-keys] Sudo.Key {ss58(hidden)} is not the account roles.sudo declares" in out


PASS = "MAINNET LAUNCH PREFLIGHT: PASS"


def test_cli_passes_root_held_by_a_nested_multisig_whose_every_key_proves_possession(clean, capsys):
    entry = nested_multisig()
    entry["members"][2]["members"][0] = role_key(fresh_ecdsa_key())
    clean.hold("sudo", entry)
    code, out = clean.run(capsys)
    assert (code, out.splitlines()[0]) == (0, PASS)


def test_cli_refuses_a_multisig_member_whose_holder_gave_no_pop(clean, capsys):
    members = [*clean.sudo_members[:2], stranger()]
    clean.hold("sudo", {"threshold": 2, "members": [*map(ss58, members[:2]), {"key": ss58(members[2])}]})
    code, out = clean.run(capsys)
    assert code == 1
    assert out.splitlines()[1:] == ["  " + no_pop("roles.sudo[0].members[2]", "sudo", "0 2"),
                                    "  " + no_provider("sudo", 2, members[2])], out


@pytest.mark.parametrize("role", ["sudo", "guardian"])
def test_cli_refuses_a_multisig_member_that_is_the_all_zero_key_with_its_no_secret_pop(clean, capsys, role):
    members = [fresh_account(), fresh_account(), ZERO_KEY]
    clean.hold(role, {"threshold": 2, "members": [
        *map(ss58, members[:2]), {"key": ss58(ZERO_KEY), "pop": "0x" + NO_SECRET_POP.hex()}]})
    code, out = clean.run(capsys)
    where = f"roles.{role}[0].members[2]"
    assert (code, out.splitlines()[1:]) == (1, ["  " + all_zero(where), "  " + no_secret(where),
                                                "  " + no_provider(role, 2, ZERO_KEY)]), out


# The red team's proof of concept: one authority's aura key replaced by the all-zero key, or its grandpa key by
# ed25519's identity, everywhere the clean launch names it, which every other rule accepts.
@pytest.mark.parametrize("kind", ["aura", "grandpa"])
def test_cli_refuses_an_authority_key_anyone_can_sign_for_wherever_the_launch_names_it(clean, capsys, kind):
    key = NO_SECRET_KEYS[kind]
    clean.members[:] = with_key(clean.members, kind, key)
    seat(clean.spec, clean.members)
    clean.launch["nodes"][0][kind] = "0x" + key.hex()
    clean.candidates = legacy_datum(clean.members)
    code, out = clean.run(capsys)
    named = [names[kind] for _, names in AUTHORITY_PLACES.values() if kind in names]
    assert (code, out.splitlines()[1:]) == (1, ["  " + no_secret_authority(where, kind, key) for where in named]), out


# A Root 2-of-2 whose other member is a key anyone holds, with how to sign as it: secret scalar 1, whose key is the
# basepoint, and the mini-secret of 32 zero bytes. Its pop verifies, so only rule 1 can see that one keyholder
# holds Root.
@pytest.mark.parametrize("label, pair", [("secret scalar 1, public", (BASEPOINT, secret_scalar(1))),
                                         ("mini-secret 0x00*32, public", sr25519.pair_from_seed(bytes(32)))],
                         ids=["basepoint", "trivial mini-secret"])
def test_cli_refuses_root_whose_other_member_anyone_holds(clean, capsys, label, pair):
    KEYHOLDERS[pair[0]] = lambda message: sr25519.sign(pair, message)
    members = [clean.sudo_members[0], pair[0]]
    clean.hold("sudo", msig(2, *members))
    code, out = clean.run(capsys)
    assert (code, out.splitlines()[1:]) == (1, [
        f"  [1 dev-keys] System.Account: {label} (sr25519) is in genesis",
        f"  [1 dev-keys] Motra.AccrualCheckpoint: {label} (sr25519) is in genesis",
        f"  [1 dev-keys] roles.endowed[3]: {label} (sr25519)",
        f"  [1 dev-keys] roles.sudo[0].members[1]: {label} (sr25519)",
        "  " + helped_holder("1 dev-keys", "roles.sudo[0]", members[0], "members[0]", ["members[1]"], SUDO_POWER)]), out


def keyed(launch: dict) -> dict:
    """The launch with each member of its sudo and guardian multisigs given as {"key": ...}, as the ceremony drafts it
    before its holders sign."""
    drafted = copy.deepcopy(launch)
    for role in ("sudo", "guardian"):
        drafted["roles"][role][0]["members"] = [{"key": key} for key in drafted["roles"][role][0]["members"]]
    return drafted


def challenge_cli(capsys, spec_path: Path, launch_path: Path, role: str, *index: str) -> tuple[int, str]:
    code = lp.main(["challenge", "--spec", str(spec_path), "--launch", str(launch_path), "--role", role,
                    "--index", *index])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


# The ceremony: draft the manifest, print each member's challenge, have its holder sign it offline as subkey sign
# --hex does, put each signature in as the member's pop, and check.
def test_cli_prints_each_members_challenge_and_passes_the_launch_its_holders_signed(clean, capsys):
    spec_path = clean.prepare()
    draft = keyed(clean.launch)
    draft_path = clean.tmp_path / "draft.json"
    draft_path.write_text(json.dumps(draft))
    signed = copy.deepcopy(draft)
    for role in ("sudo", "guardian"):
        for j, member in enumerate(signed["roles"][role][0]["members"]):
            code, printed = challenge_cli(capsys, spec_path, draft_path, role, "0", str(j))
            assert (code, printed) == (0, "0x" + challenge(lp.load_spec(str(spec_path)), draft, role, (0, j)).hex()
                                       + "\n")
            member["pop"] = "0x" + KEYHOLDERS[lp.decode_public_key(member["key"])](
                bytes.fromhex(printed.strip()[2:])).hex()
    code, out = run_cli(clean.tmp_path, spec_path, signed, capsys, clean.kupo.url, clean.launch_key,
                        signed_launch=draft)
    assert (code, out.splitlines()[0]) == (0, PASS)


@pytest.mark.parametrize("role, index", [
    ("sudo", ["0"]), ("sudo", ["0", "3"]), ("sudo", ["1", "0"]), ("sudo", ["0", "0", "0"]), ("sudo", ["0", "-1"]),
    ("anchor_signer", ["0", "0"]), ("treasury", ["0", "0"]),
], ids=["the multisig itself", "past its members", "past the role's entries", "deeper than a member",
        "a negative index", "a role entry that is no multisig", "an undeclared role"])
def test_cli_challenge_names_only_a_multisig_member(clean, capsys, role, index):
    spec_path = clean.prepare()
    launch_path = clean.tmp_path / "draft.json"
    launch_path.write_text(json.dumps(keyed(clean.launch)))
    code, out = challenge_cli(capsys, spec_path, launch_path, role, *index)
    assert (code, out) == (2, f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) roles.{role} has no multisig member at "
                              f"index {' '.join(index)}: give the multisig's index in the role, then the member's "
                              "index in each multisig down to it\n")


# A bare member's challenge would bind a launch manifest that changes once the member is given as {"key": ...}.
def test_cli_challenge_for_a_member_given_as_a_bare_key_is_an_input_error(clean, capsys):
    spec_path = clean.prepare()
    launch_path = clean.tmp_path / "launch.json"
    launch_path.write_text(json.dumps(clean.launch))
    code, out = challenge_cli(capsys, spec_path, launch_path, "guardian", "0", "1")
    assert (code, out) == (2, "MAINNET LAUNCH PREFLIGHT: REFUSE (input) roles.guardian[0].members[1] is a bare key: "
                              'give it as {"key": ...} before its holder signs, since its challenge binds the launch '
                              "manifest as it reads once the pop goes in\n")


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
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: issuance_of(clean.spec) - 1})
    code, out = clean.run(capsys)
    assert code == 1
    assert "the difference is MATRA no cMATRA backs" in out


def test_cli_refuses_a_pending_withdrawal_planted_in_raw_genesis(clean, capsys):
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: 10**30})
    clean.spec.storage[map_key("Billing", "PendingWithdrawals", fresh_account())] = \
        (10**30).to_bytes(16, "little") + bytes(4)
    code, out = clean.run(capsys)
    assert code == 1
    assert "[4 supply] genesis sets Billing.PendingWithdrawals (1 entry), which a mainnet genesis may not set" in out


def test_cli_refuses_a_negative_economics_value_as_unreadable(clean, capsys):
    signed = copy.deepcopy(clean.launch)
    clean.launch["economics"]["era_cap_base"] = -1
    code, out = clean.run(capsys, signed_launch=signed)
    assert code == 2 and "economics.era_cap_base must be a non-negative integer" in out


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
    cross_chain = cross_chain_of(ALICE)
    clean.candidates = legacy_datum([(cross_chain, ALICE, fresh_account())])
    clean.launch["nodes"].append(clean.authority("val9", ALICE, fresh_account(), cross_chain))
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
    ({"roles": {}, "economics": {"era_cap_base": -1}, "supply": VALID_LOCK},
     "economics.era_cap_base must be a non-negative integer"),
    ({"roles": {}, "economics": {"era_cap_base": True}, "supply": VALID_LOCK},
     "economics.era_cap_base must be a non-negative integer"),
    ({"roles": {}, "economics": {"fee_buffer": 0}, "supply": VALID_LOCK}, "unknown economics field fee_buffer"),
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
                    "--manifest-key", "0x00", "--kupo", "http://127.0.0.1:9", "--subwasm", "subwasm",
                    "--extra-well-known", str(plain)])
    assert code == 2
    assert "needs the raw chain spec" in capsys.readouterr().err


# The runtime a spec carries pins another chain's genesis into settlement's or the oracle's signed payloads, or a
# later pallet pins one of its own: every signature the chain's committee makes fails from block one.
@pytest.mark.parametrize("constant", ["IntentSettlement.MateriosChainId", "Oracle.MateriosChainId",
                                      "Bridge.GenesisHash", "IntentSettlement.MainchainGenesisHash"])
def test_a_spec_runtime_that_holds_another_chain_id_is_refused(tmp_path, preprod_path, constant):
    other = bytes([37]) * 32
    node = attested(tmp_path, preprod_path, exe=fake_node(tmp_path, chain_ids={constant: list(other)}))
    assert node_findings(preprod_path, node) == [
        f"[8 node] authority val0: the spec's runtime holds {constant} 0x{other.hex()} at block one, not the genesis "
        f"hash 0x{preprod_genesis_hex(preprod_path)}: a payload signed for this chain does not verify on it"]


def test_a_node_binary_with_no_chain_id_is_an_input_error(tmp_path, preprod_path):
    node = attested(tmp_path, preprod_path, exe=fake_node(tmp_path, no_chain_id=True))
    with pytest.raises(lp.InputError, match="authority val0: its node binary's chain-id failed: error: unrecognized "
                                            "subcommand 'chain-id'"):
        node_findings(preprod_path, node)


def chain_id_report(monkeypatch, report) -> None:
    """Every node run answers with `report` as its chain-id output."""
    monkeypatch.setattr(lp.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, report, ""))


GENESIS = bytes([31]) * 32


def chain_ids(genesis: bytes = GENESIS, **ids: bytes) -> list:
    return [[*name.split("."), list(value)] for name, value in
            {"IntentSettlement.MateriosChainId": genesis, "Oracle.MateriosChainId": genesis, **ids}.items()]


MAINNET_IDS = (CARDANO_MAINNET_MAGIC, CARDANO_MAINNET_SHELLEY, AEGIS_POLICY)


def reported(ids=MAINNET_IDS) -> dict:
    """Cardano ids as the node's chain-id reports them."""
    magic, shelley, aegis = ids
    return {"network_magic": magic, "mainchain_genesis_hash": list(shelley), "aegis_policy_v1_script_hash": list(aegis)}


def report(genesis: bytes = GENESIS, cardano=MAINNET_IDS, **fields) -> str:
    return json.dumps({"genesis_hash": "0x" + genesis.hex(), "constants": chain_ids(genesis),
                       "cardano_ids": cardano and reported(cardano), **fields})


@pytest.mark.parametrize("report", [
    "", "null", "[]", "{}", json.dumps({"genesis_hash": "0x" + GENESIS.hex()}),
    json.dumps({"genesis_hash": "0x00", "constants": []}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex().upper(), "constants": []}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": {}}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": [["Oracle", "MateriosChainId"]]}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": [["Oracle", "MateriosChainId", [256]]]}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": [["Oracle", "MateriosChainId", [True]]]}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": [["Oracle", 7, list(GENESIS)]]}),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": chain_ids() + chain_ids()[:1]}),
    '{"genesis_hash": "0x%s", "genesis_hash": "0x%s", "constants": []}' % (GENESIS.hex(), GENESIS.hex()),
    json.dumps({"genesis_hash": "0x" + GENESIS.hex(), "constants": chain_ids()}),
    report(cardano_ids=[]),
    report(cardano_ids={**reported(), "network_magic": 2 ** 32}),
    report(cardano_ids={**reported(), "network_magic": True}),
    report(cardano_ids={**reported(), "mainchain_genesis_hash": list(bytes(31))}),
    report(cardano_ids={**reported(), "aegis_policy_v1_script_hash": [256] * 28}),
    report(cardano_ids={**reported(), "network": 1}),
    report(cardano_ids={key: value for key, value in reported().items() if key != "network_magic"}),
], ids=["empty", "null", "list", "no-fields", "no-constants", "short-hash", "upper-hex", "constants-object",
        "two-field-constant", "byte-past-255", "bool-byte", "number-name", "repeated-constant", "repeated-key",
        "no-cardano-ids", "cardano-ids-list", "magic-past-u32", "bool-magic", "short-shelley", "aegis-byte-past-255",
        "unknown-cardano-field", "no-magic"])
def test_an_unreadable_chain_id_report_is_an_input_error(monkeypatch, tmp_path, report):
    chain_id_report(monkeypatch, report)
    with pytest.raises(lp.InputError, match="authority val0: its node's chain-id"):
        lp.check_runtime_chain_ids(tmp_path / "node", tmp_path / "spec", GENESIS, MAINNET_IDS, "authority val0")


@pytest.mark.parametrize("cardano", [MAINNET_IDS, None], ids=["stored", "none-stored"])
def test_a_chain_id_report_of_the_genesis_and_the_cardano_ids_the_preflight_reads_passes(monkeypatch, tmp_path,
                                                                                          cardano):
    chain_id_report(monkeypatch, report(cardano=cardano))
    assert lp.check_runtime_chain_ids(tmp_path / "node", tmp_path / "spec", GENESIS, cardano, "authority val0") == []


@pytest.mark.parametrize("node_reads", [(1, CARDANO_MAINNET_SHELLEY, AEGIS_POLICY), None], ids=["other", "none"])
def test_a_chain_id_report_reading_other_cardano_ids_than_the_preflight_is_refused(monkeypatch, tmp_path, node_reads):
    """The node reads IntentSettlement.CardanoIds with the runtime's own types: another reading means the preflight
    decodes the item apart from the chain, and rule 11 checked other ids than the chain binds."""
    chain_id_report(monkeypatch, report(cardano=node_reads))
    node_said = ("none" if node_reads is None else
                 f"network magic 1, Shelley genesis hash 0x{CARDANO_MAINNET_SHELLEY.hex()}, aegis_policy_v1 script "
                 f"hash 0x{AEGIS_POLICY.hex()}")
    assert messages(lp.check_runtime_chain_ids(tmp_path / "node", tmp_path / "spec", GENESIS, MAINNET_IDS,
                                               "authority val0")) == [
        f"[8 node] authority val0: its node's chain-id reads IntentSettlement.CardanoIds as {node_said} from the "
        f"checked chain spec, and the preflight reads network magic {CARDANO_MAINNET_MAGIC}, Shelley genesis hash "
        f"0x{CARDANO_MAINNET_SHELLEY.hex()}, aegis_policy_v1 script hash 0x{AEGIS_POLICY.hex()}: rule 11 checked "
        "other ids than the chain binds"]


def test_a_chain_id_report_built_on_another_genesis_is_refused(monkeypatch, tmp_path):
    other = bytes([33]) * 32
    chain_id_report(monkeypatch, report(other, cardano=None))
    assert messages(lp.check_runtime_chain_ids(tmp_path / "node", tmp_path / "spec", GENESIS, None,
                                               "authority val0")) == [
        f"[8 node] authority val0: its node's chain-id builds genesis 0x{other.hex()} from the checked chain spec, and "
        f"the preflight computes 0x{GENESIS.hex()}"]


# ---------------------------------------------------------------------------
# What a keyholder's proof binds, and what the launch key alone signs
# ---------------------------------------------------------------------------

# Each field the readers of a launch manifest take, as its classification names it: a field of an object by its
# path, an entry of a list as []. A role's entries are one field, less each member's pop, which is the proof itself.
def manifest_schema() -> set[str]:
    objects = {"economics": lp.ECONOMICS_FIELDS, "supply.genesis_lock": lp.GENESIS_LOCK_FIELDS,
               "partner_chain": lp.PARTNER_CHAIN_FIELDS, "settlement": lp.SETTLEMENT_FIELDS,
               "cardano_follower": set(lp.CARDANO_MAINNET_FOLLOWER), "nodes[]": lp.NODE_FIELDS,
               "rpc_proxies[]": lp.PROXY_FIELDS}
    whole = lp.LAUNCH_FIELDS - {"economics", "supply", "partner_chain", "settlement", "cardano_follower", "nodes",
                                "rpc_proxies"}
    return whole | {f"{path}.{field}" for path, fields in objects.items() for field in fields}


def test_every_manifest_field_is_classified_exactly_once():
    """The classification names exactly the fields the readers take, and names none twice: a dict keeps the last of
    a key its source repeats, so the source is read."""
    assert set(lp.MANIFEST_FIELDS) == manifest_schema()
    assert set(lp.MANIFEST_FIELDS.values()) == {lp.GENESIS, lp.DEPLOYMENT}
    table = next(node.value for node in ast.parse((HERE / "launch_preflight.py").read_text()).body
                 if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "MANIFEST_FIELDS")
    assert sorted(key.value for key in table.keys) == sorted(lp.MANIFEST_FIELDS)


def test_a_manifest_field_the_classification_does_not_name_is_refused():
    with pytest.raises(lp.InputError, match="nodes\\[\\].region is a launch manifest field no binding is given for"):
        lp.genesis_content({"nodes": [{"authority": True, "region": "eu"}]})


# What the proofs must bind whatever else moves: the binary that builds the genesis and runs it, each authority's
# keys, who holds the lock, and every field the chain spec is built from.
PROOF_BOUND = {"roles", "dust", "attestation_threshold", "slots_per_epoch", "later_signers", "no_standby",
               "nodes[].authority", "nodes[].aura",
               "nodes[].grandpa", "nodes[].cross_chain", "nodes[].exe_sha256", "supply.genesis_lock.address",
               "supply.genesis_lock.native_script",
               *(f"economics.{field}" for field in lp.ECONOMICS_FIELDS),
               *(f"partner_chain.{field}" for field in lp.PARTNER_CHAIN_FIELDS),
               *(f"settlement.{field}" for field in lp.SETTLEMENT_FIELDS),
               *(f"cardano_follower.{field}" for field in lp.CARDANO_MAINNET_FOLLOWER)}


def test_the_proofs_bind_the_genesis_the_binary_and_the_lock_holders_and_nothing_of_the_deployment():
    assert {field for field, binding in lp.MANIFEST_FIELDS.items() if binding == lp.GENESIS} == PROOF_BOUND


def other_hash(digits: int = 64) -> str:
    return "0x" + os.urandom(digits // 2).hex()


def edit_node(field: str, value):
    """Give the first authority's `field` another value; for a field only another kind of node takes, a new one."""
    def edit(launch: dict) -> None:
        launch["nodes"][0][field] = value(launch["nodes"][0].get(field)) if callable(value) else value
    return edit


def edit_at(path: str, value):
    def edit(launch: dict) -> None:
        *parents, field = path.split(".")
        target = launch
        for parent in parents:
            target = target[parent]
        target[field] = value(target.get(field)) if callable(value) else value
    return edit


def rekey_a_role(launch: dict) -> None:
    launch["roles"]["anchor_signer"] = [ss58(fresh_account())]


def endow_one_more(launch: dict) -> None:
    accounts = next(iter(launch["dust"].values()))
    accounts[next(iter(accounts))] += 1


def edit_proxy(field: str, value):
    def edit(launch: dict) -> None:
        launch["rpc_proxies"][0][field] = value
    return edit


# One edit of each field of the manifest, by its classification's name: a value the readers take, other than the
# clean launch's.
FIELD_EDITS = {
    "roles": rekey_a_role,
    "dust": endow_one_more,
    "attestation_threshold": edit_at("attestation_threshold", lambda threshold: threshold + 1),
    "slots_per_epoch": edit_at("slots_per_epoch", 300),
    "later_signers": edit_at("later_signers", lambda signers: signers + 1),
    "no_standby": edit_at("no_standby", ["anchor_signer"]),
    "public_rpc": edit_at("public_rpc", lambda urls: [*urls, "https://rpc-2.example.org/rpc"]),
    "economics.attestation_reward_per_signer": edit_at("economics.attestation_reward_per_signer", 1),
    "economics.era_cap_base": edit_at("economics.era_cap_base", 7),
    "economics.era_cap_baseline_attestor_count": edit_at("economics.era_cap_baseline_attestor_count", 33),
    "economics.validator_reward_per_era": edit_at("economics.validator_reward_per_era", 1),
    "economics.treasury_emission_share_perbill": edit_at("economics.treasury_emission_share_perbill", 1),
    "supply.genesis_lock.utxo": edit_at("supply.genesis_lock.utxo", "ab" * 32 + "#0"),
    "supply.genesis_lock.address": edit_at("supply.genesis_lock.address", "addr1w" + "q" * 52),
    "supply.genesis_lock.native_script": edit_at("supply.genesis_lock.native_script", "0x8200581c" + "11" * 28),
    "partner_chain.genesis_utxo": edit_at("partner_chain.genesis_utxo", "cd" * 32 + "#1"),
    "partner_chain.committee_candidate_address": edit_at("partner_chain.committee_candidate_address",
                                                         "addr1w" + "p" * 52),
    "partner_chain.d_parameter_policy_id": edit_at("partner_chain.d_parameter_policy_id", other_hash(56)),
    "partner_chain.permissioned_candidates_policy_id": edit_at("partner_chain.permissioned_candidates_policy_id",
                                                               other_hash(56)),
    "settlement.aegis_policy_v1_script_hash": edit_at("settlement.aegis_policy_v1_script_hash", None),
    **{f"cardano_follower.{name}": edit_at(f"cardano_follower.{name}", lambda value: value + "0")
       for name in lp.CARDANO_MAINNET_FOLLOWER},
    "nodes[].name": edit_node("name", "validator-one"),
    "nodes[].host": edit_node("host", "validator-one.internal"),
    "nodes[].addresses": edit_node("addresses", ["10.9.8.7"]),
    "nodes[].argv": edit_node("argv", lambda argv: [*argv, "--reserved-nodes", "/dns/val9/tcp/30333/p2p/12D3"]),
    "nodes[].env": edit_node("env", lambda env: dict(env, DB_SYNC_POSTGRES_CONNECTION_STRING="db-9:5432/cexplorer")),
    "nodes[].authority": edit_node("authority", False),
    "nodes[].aura": edit_node("aura", lambda _: "0x" + fresh_account().hex()),
    "nodes[].grandpa": edit_node("grandpa", lambda _: "0x" + fresh_account().hex()),
    "nodes[].cross_chain": edit_node("cross_chain", lambda _: "0x" + cross_chain_key().hex()),
    "nodes[].exe_sha256": edit_node("exe_sha256", lambda _: other_hash()),
    **{f"nodes[].{field}": edit_node(field, lambda path: path + ".retaken")
       for field in ("cmdline", "exe", "chain_spec", "served_genesis", "served_chain", "served_chain_type",
                     "served_properties", "process_stat", "system_stat", "chain_spec_stat")},
    "rpc_proxies[].name": edit_proxy("name", "public-rpc-2"),
    "rpc_proxies[].node": edit_proxy("node", "val1"),
    "rpc_proxies[].kind": edit_proxy("kind", "nginx-dump"),
    "rpc_proxies[].config": edit_proxy("config", "/etc/nginx/other.conf"),
    "rpc_proxies[].other_targets": edit_proxy("other_targets", ["rpc-node:9944", "status.example.org:443"]),
}


def test_every_manifest_field_has_an_edit():
    assert set(FIELD_EDITS) == manifest_schema()


def signed_and_proven(clean) -> tuple[lp.Spec, dict, dict]:
    """The clean launch as its ceremony leaves it: every keyholder's proof in, then the launch key's signature."""
    spec = lp.load_spec(str(clean.spec_path()))
    launch = prove(clean.launch, spec)
    return spec, launch, lp.signed_manifest(spec, launch, clean.launch_key)


def members_of(launch: dict) -> list[tuple[str, str, str]]:
    return [(where, role, " ".join(map(str, position))) for role, where, position, _ in lp.multisig_members(launch)]


MANIFEST_EDITED = "[6 checkpoint] launch_manifest_hash is 0x"


def checkpoint_findings(clean, spec, launch, signed) -> list[str]:
    return messages(lp.check_checkpoint(spec, launch, signed, [pub(clean.launch_key)]))


@pytest.mark.parametrize("field", sorted(field for field in FIELD_EDITS if field not in PROOF_BOUND))
def test_an_edit_to_a_deployment_field_leaves_every_proof_valid_and_needs_a_new_launch_signature(clean, field):
    spec, launch, signed = signed_and_proven(clean)
    edited = copy.deepcopy(launch)
    FIELD_EDITS[field](edited)
    assert edited != launch
    assert len(members_of(edited)) == 5 and possession_findings(spec, edited) == []
    refused = checkpoint_findings(clean, spec, edited, signed)
    assert len(refused) == 1 and refused[0].startswith(MANIFEST_EDITED)
    assert checkpoint_findings(clean, spec, edited, lp.signed_manifest(spec, edited, clean.launch_key)) == []


@pytest.mark.parametrize("field", sorted(PROOF_BOUND))
def test_an_edit_to_a_genesis_field_voids_every_proof(clean, field):
    spec, launch, signed = signed_and_proven(clean)
    edited = copy.deepcopy(launch)
    FIELD_EDITS[field](edited)
    assert edited != launch
    assert possession_findings(spec, edited) == [unproven(where, "sr25519", role, index)
                                                 for where, role, index in members_of(edited)]
    assert any(reason.startswith(MANIFEST_EDITED) for reason in checkpoint_findings(clean, spec, edited, signed))


def test_a_pop_is_bound_by_neither_hash(clean):
    """A proof is what is verified: the launch signature may come before it, and it voids no other member's."""
    spec, launch, signed = signed_and_proven(clean)
    draft = copy.deepcopy(launch)
    del draft["roles"]["guardian"][0]["members"][1]["pop"]
    assert lp.genesis_content_hash(draft) == lp.genesis_content_hash(launch)
    assert checkpoint_findings(clean, spec, draft, signed) == []
    assert possession_findings(spec, draft) == [no_pop("roles.guardian[0].members[1]", "guardian", "0 1")]


def test_the_genesis_content_is_the_same_whatever_the_order_of_the_nodes_and_whichever_nodes_are_no_authority(clean):
    launch = clean.launch
    edge = {"name": "edge-0", "host": "edge-0", "authority": False}
    shuffled = dict(launch, nodes=[edge, *reversed(launch["nodes"])])
    without_edge = dict(launch, nodes=[node for node in launch["nodes"] if node["authority"]])
    assert lp.genesis_content_hash(shuffled) == lp.genesis_content_hash(launch) == lp.genesis_content_hash(without_edge)


def test_an_authority_keeps_its_own_binary_pin(clean):
    """Two authorities' pins swapped pin the same two binaries, to other keys: each authority's pin is bound with
    its keys."""
    swapped = copy.deepcopy(clean.launch)
    swapped["nodes"][0]["exe_sha256"], swapped["nodes"][1]["exe_sha256"] = other_hash(), other_hash()
    twice = copy.deepcopy(swapped)
    twice["nodes"][0]["exe_sha256"], twice["nodes"][1]["exe_sha256"] = (swapped["nodes"][1]["exe_sha256"],
                                                                       swapped["nodes"][0]["exe_sha256"])
    assert lp.genesis_content_hash(twice) != lp.genesis_content_hash(swapped)


def test_the_genesis_content_hash_is_the_tagged_canonical_json_of_the_genesis_bound_fields(clean):
    assert lp.genesis_content_hash(clean.launch) == genesis_content_hash(clean.launch)
    content = lp.genesis_content(clean.launch)
    assert set(content) == {"roles", "dust", "attestation_threshold", "economics", "supply", "partner_chain",
                            "slots_per_epoch", "settlement", "cardano_follower", "nodes", "later_signers"}
    assert content["supply"] == {"genesis_lock": {field: LOCK[field] for field in ("address", "native_script")}}
    assert all(set(node) == {"authority", "aura", "grandpa", "cross_chain", "exe_sha256"} for node in content["nodes"])
    assert len(content["nodes"]) == 4


def test_a_challenge_binds_its_members_key(spec):
    """The same role and position under another key is another challenge: a holder cannot be handed the challenge of
    the key that stood there before."""
    member, other = fresh_account(), fresh_account()
    launch = prove({"roles": {"sudo": [msig(2, fresh_account(), member)]}}, spec)
    context = launch_context(spec, launch)
    assert member_challenge(context, "sudo", (0, 1), member) != member_challenge(context, "sudo", (0, 1), other)
    assert lp.possession_challenge(lp.possession_context(spec, launch), "sudo", (0, 1), member) == member_challenge(
        context, "sudo", (0, 1), member)
    assert member_challenge(context, "sudo", (0, 1), member).endswith(b"\x80" + member)


# The rehearsal's negative case: a host renamed on a node that is no authority, after the ceremony.
def test_cli_a_deployment_edit_after_the_ceremony_keeps_every_proof_and_needs_a_new_launch_signature(clean, capsys):
    spec_path = clean.prepare()
    proven = prove(clean.launch, lp.load_spec(str(spec_path)))
    edited = copy.deepcopy(proven)
    edited["nodes"][-1]["host"] = "edge.renamed.internal"
    assert not edited["nodes"][-1]["authority"]
    code, out = run_cli(clean.tmp_path, spec_path, edited, capsys, clean.kupo.url, clean.launch_key,
                        signed_launch=proven)
    assert code == 1 and out.count("\n") == 2 and out.splitlines()[1].startswith("  " + MANIFEST_EDITED), out
    code, out = run_cli(clean.tmp_path, spec_path, edited, capsys, clean.kupo.url, clean.launch_key)
    assert (code, out.splitlines()[0]) == (0, PASS), out


def test_cli_an_authority_repinned_to_another_binary_after_the_ceremony_voids_every_proof(clean, capsys):
    """The launch key alone cannot move an authority to another node build: the keyholders' proofs bind each pin."""
    spec_path = clean.prepare()
    proven = prove(clean.launch, lp.load_spec(str(spec_path)))
    other = fake_node(clean.tmp_path, log=str(clean.tmp_path / "other-binary.jsonl"))
    edited = copy.deepcopy(proven)
    edited["nodes"][0].update(exe=str(other), exe_sha256=sha256_pin(other))
    code, out = run_cli(clean.tmp_path, spec_path, edited, capsys, clean.kupo.url, clean.launch_key)
    assert code == 1, out
    assert out.splitlines()[1:] == ["  " + unproven(where, "sr25519", role, index)
                                    for where, role, index in members_of(edited)], out


# ---------------------------------------------------------------------------
# Rule 9: the settings without which an authority authors nothing, or does not start
# ---------------------------------------------------------------------------

def settings_findings(env: dict, script: str | None = None) -> list[str]:
    return messages(lp.check_authority_settings({"nodes": [follower_node(env=env, script=script)]}))


NO_BENEFICIARY = ("[9 committee] authority val1 does not set SIDECHAIN_BLOCK_BENEFICIARY: its node's block proposer "
                  "reads from it the 32 bytes its blocks are counted under, and without it the node syncs, keeps its "
                  "peers and authors no block")
NO_BACKEND = ("[9 committee] authority val1 does not set MAIN_CHAIN_FOLLOWER: declare the Cardano follower its node "
              "reads Cardano through, db-sync or yaci")
NO_DATABASE = ("[9 committee] authority val1 does not set DB_SYNC_POSTGRES_CONNECTION_STRING, the database its "
               "Cardano follower reads: a node with none does not start")
NO_MARGIN = ("[9 committee] authority val1 does not set BLOCK_STABILITY_MARGIN: its Cardano follower does not start "
             "without it")


def test_an_authority_with_its_beneficiary_and_follower_backend_passes():
    assert settings_findings(AUTHORITY_ENV) == []
    exports = "; ".join(f"export {name}={value}" for name, value in AUTHORITY_ENV.items())
    assert settings_findings({}, f"{exports}; exec materios-node --validator") == []
    assert settings_findings(dict(AUTHORITY_ENV, MAIN_CHAIN_FOLLOWER="yaci")) == []


@pytest.mark.parametrize("name, reason", [
    ("SIDECHAIN_BLOCK_BENEFICIARY", NO_BENEFICIARY), ("MAIN_CHAIN_FOLLOWER", NO_BACKEND),
    ("DB_SYNC_POSTGRES_CONNECTION_STRING", NO_DATABASE), ("BLOCK_STABILITY_MARGIN", NO_MARGIN)])
def test_an_authority_that_leaves_a_setting_its_node_needs_out_is_refused(name, reason):
    assert settings_findings({key: value for key, value in AUTHORITY_ENV.items() if key != name}) == [reason]


def test_a_node_that_is_no_authority_needs_none_of_them():
    assert lp.check_authority_settings({"nodes": [{"name": "edge", "host": "edge", "authority": False}]}) == []


@pytest.mark.parametrize("value", ["0x" + "ab" * 31, "0x" + "ab" * 33, "ab" * 31, "0x" + "zz" * 32, "", "5Grw"],
                         ids=["31 bytes", "33 bytes", "31 bytes and no 0x", "no hex", "empty", "an address"])
def test_a_beneficiary_that_is_not_32_bytes_of_hex_is_refused(value):
    assert settings_findings(dict(AUTHORITY_ENV, SIDECHAIN_BLOCK_BENEFICIARY=value)) == [
        "[9 committee] authority val1 sets SIDECHAIN_BLOCK_BENEFICIARY to other than the 64 hex digits of 32 bytes, "
        "with or without 0x: its node's block proposer reads no other value, and the node authors no block"]


@pytest.mark.parametrize("value", ["0x" + "ab" * 32, "ab" * 32, "AB" * 32])
def test_a_beneficiary_is_read_in_each_spelling_the_node_reads(value):
    assert settings_findings(dict(AUTHORITY_ENV, SIDECHAIN_BLOCK_BENEFICIARY=value)) == []


@pytest.mark.parametrize("value", ["mock", "dbsync", "Yaci", "", "db-sync "])
def test_a_follower_backend_other_than_db_sync_or_yaci_is_refused(value):
    assert settings_findings(dict(AUTHORITY_ENV, MAIN_CHAIN_FOLLOWER=value)) == [
        f"[9 committee] authority val1 sets MAIN_CHAIN_FOLLOWER to {value!r}, not db-sync or yaci: its node reads any "
        "value but yaci, in any case, as db-sync"]


PASSWORD = "hunter2-" + "s3cr3t"


@pytest.mark.parametrize("value", [
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer", "postgres://db-1:5432/cexplorer", "db-1/cexplorer",
    "db-1:5432", "db-1:port/cexplorer", f"db-1:5432/cexplorer?password={PASSWORD}", ""],
    ids=["a URL with its password", "a URL", "no port", "no database", "no port number", "a query", "empty"])
def test_a_connection_string_declared_in_another_form_than_the_capture_writes_is_refused_without_echoing_it(value):
    assert settings_findings(dict(AUTHORITY_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING=value)) == [
        "[9 committee] authority val1 gives DB_SYNC_POSTGRES_CONNECTION_STRING in another form than "
        "<host>:<port>/<database>, as capture_environ.py writes what its node runs with: the manifest is signed and "
        "handed round, and holds no user or password"]


@pytest.mark.parametrize("value", ["db-1.internal:5432/cexplorer", "10.0.0.5:6432/yaci_store", "[fd00::5]:5432/db"])
def test_a_connection_string_declared_as_host_port_and_database_passes(value):
    assert settings_findings(dict(AUTHORITY_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING=value)) == []


@pytest.mark.parametrize("value", ["", "-1", "0x10", "1.5", "4294967296", "ten"])
def test_a_stability_margin_that_is_no_u32_is_refused(value):
    assert settings_findings(dict(AUTHORITY_ENV, BLOCK_STABILITY_MARGIN=value)) == [
        f"[9 committee] authority val1 sets BLOCK_STABILITY_MARGIN to {value!r}, not a number of Cardano blocks from "
        "0 to 4294967295 in decimal: its Cardano follower does not start on another value"]


def test_the_mainnet_fixtures_authorities_set_what_their_nodes_need(mainnet):
    _, _, launch = mainnet
    assert [sorted(set(node["env"]) - set(MAINNET_FOLLOWER)) for node in launch["nodes"]] == [
        sorted(set(AUTHORITY_ENV) - set(MAINNET_FOLLOWER))] * 4
    assert lp.check_authority_settings(launch) == []


# The rehearsal's validator restarted without its beneficiary logged "Unable to author block in slot" at every slot.
def test_cli_refuses_an_authority_with_no_block_beneficiary(clean, capsys):
    del clean.launch["nodes"][2]["env"]["SIDECHAIN_BLOCK_BENEFICIARY"]
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(out, NO_BENEFICIARY.replace("val1", "val2")), out


def test_cli_refuses_an_authority_that_declares_no_follower_backend(clean, capsys):
    for name in ("MAIN_CHAIN_FOLLOWER", "DB_SYNC_POSTGRES_CONNECTION_STRING"):
        del clean.launch["nodes"][0]["env"][name]
    code, out = clean.run(capsys)
    assert (code, out.splitlines()[1:]) == (1, ["  " + reason.replace("val1", "val0")
                                                for reason in (NO_BACKEND, NO_DATABASE)]), out


# ---------------------------------------------------------------------------
# The environment a running node process was started with
# ---------------------------------------------------------------------------

SECRET_TOKEN = "tok-" + "9f8e7d6c5b4a"


RUNNING_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin", "HOME": "/var/lib/materios", "LANG": "C.UTF-8",
    "INVOCATION_ID": "0f0e0d0c0b0a09080706050403020100", "RUST_LOG": "info", "API_TOKEN": SECRET_TOKEN,
    **MAINNET_FOLLOWER, "MAIN_CHAIN_FOLLOWER": "db-sync", "BLOCK_STABILITY_MARGIN": "0",
    "DB_SYNC_POSTGRES_CONNECTION_STRING": f"postgres://materios:{PASSWORD}@db-1.internal:5432/cexplorer",
    "SIDECHAIN_BLOCK_BENEFICIARY": "0x" + "ab" * 32,
}


def test_the_capture_keeps_the_settings_the_preflight_reads_and_reduces_the_connection_string():
    assert capture_environ.captured(environ_block(RUNNING_ENV)) == AUTHORITY_ENV


def test_the_capture_holds_no_password_user_or_setting_outside_its_names():
    written = capture_environ.written(capture_environ.captured(environ_block(RUNNING_ENV)), (NODE_PID, 77))
    for secret in (PASSWORD, "materios:", SECRET_TOKEN, "API_TOKEN", "/var/lib/materios", "INVOCATION_ID"):
        assert secret.encode() not in written
    assert written == capture_block(AUTHORITY_ENV, NODE_PID, 77)
    assert capture_environ.read(written) == (AUTHORITY_ENV, (NODE_PID, 77))


def test_the_capture_names_every_setting_an_authority_declares_and_the_ones_it_may_not_run_with():
    declared = lp.AUTHORITY_SETTINGS - {"RUST_LOG", "RUST_BACKTRACE", "RUST_LIB_BACKTRACE", "TZ"}
    assert declared < capture_environ.CAPTURED
    assert capture_environ.CAPTURED - declared == {
        "USE_MAIN_CHAIN_FOLLOWER_MOCK", "MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE", "MITHRIL_CLIENT_BIN",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", *SQLX_SETTINGS}


# What sqlx-postgres 0.7.4 reads from the environment for a connection (options/mod.rs, options/pgpass.rs).
SQLX_SETTINGS = ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY",
                 "PGSSLMODE", "PGAPPNAME", "PGOPTIONS", "PGPASSFILE")


@pytest.mark.parametrize("url, reduced", [
    (f"postgres://materios:{PASSWORD}@db-1.internal:5432/cexplorer", "db-1.internal:5432/cexplorer"),
    (f"postgresql://materios:{PASSWORD}@10.0.0.5:6432/yaci_store?sslmode=require", "10.0.0.5:6432/yaci_store"),
    ("postgres://materios@DB-1.Internal:5432/cexplorer", "db-1.internal:5432/cexplorer"),
    (f"postgres://materios:{PASSWORD}@[fd00::5]:5432/cexplorer", "[fd00::5]:5432/cexplorer"),
    (f"postgres://materios:{PASSWORD}@db-1/?port=6432&dbname=other&password={PASSWORD}", "db-1:6432/other"),
    ("postgres:///cexplorer?host=/var/run/postgresql&port=5432", "/var/run/postgresql:5432/cexplorer"),
    (f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?sslmode=verify-full&sslrootcert=/etc/ssl/db.pem"
     "&application_name=materios", "db-1:5432/cexplorer"),
])
def test_a_connection_string_is_reduced_to_its_host_port_and_database(url, reduced):
    assert capture_environ.reduced_connection(url) == reduced


@pytest.mark.parametrize("url", [
    f"postgres://materios:{PASSWORD}@db-1/cexplorer", f"postgres://materios:{PASSWORD}@db-1:5432",
    f"postgres://materios:{PASSWORD}@:5432/cexplorer", f"host=db-1 port=5432 password={PASSWORD} dbname=cexplorer",
    f"postgres://materios:pa/{PASSWORD}@db-1:5432/cexplorer", f"mysql://materios:{PASSWORD}@db-1:5432/cexplorer",
    f"postgres://materios:{PASSWORD}@db-1:port/cexplorer", "",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?options=-c%20search_path%3Dfake",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?options[search_path]=fake",
    f"postgres://materios:{PASSWORD}@ignored:5432/cexplorer?host=/var/run/evil&host=db-1",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?host=/var/run/evil",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?host=db-2",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?hostaddr=10.9.9.9",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?port=6432",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer?dbname=other",
    f"postgres://user:8080/{PASSWORD}?@db-1:5432/cexplorer", f"postgres://user:12/{PASSWORD}#@db-1:5432/cexplorer",
    f"postgres://db-1:5432/cexplorer?user=u@v&password={PASSWORD}",
    f"postgres://materios:{PASSWORD}@db-1:5432/cexplorer#x@y"],
    ids=["no port", "no database", "no host", "no URL", "a slash in the password", "another scheme",
         "a port that is no number", "empty", "session options", "one session option", "a socket and then a host",
         "a host and a socket", "two hosts", "a host and a host address", "two ports", "two databases",
         "an @ in the query", "an @ in the fragment", "an @ in a parameter", "an @ after the database"])
def test_a_connection_string_the_capture_cannot_reduce_is_refused_without_its_value(url):
    with pytest.raises(ValueError) as refused:
        capture_environ.captured(environ_block(dict(RUNNING_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING=url)))
    assert str(refused.value) == (
        "DB_SYNC_POSTGRES_CONNECTION_STRING is not a postgres:// URL that names its host, port and database, so it "
        "cannot be reduced to <host>:<port>/<database>; its value is not shown")
    assert PASSWORD not in repr(refused.value)


# How the node's most forgiving reader takes a name: figment trims it, matches it and the MC__ prefix without regard
# to ASCII case, trims again what follows the prefix, and nests at a dot.
NAMES_READ_AS = {
    "BLOCK_STABILITY_MARGIN": "BLOCK_STABILITY_MARGIN",
    "BLOCK_STABILITY_MARGIN ": "BLOCK_STABILITY_MARGIN",
    " CARDANO_SECURITY_PARAMETER": "CARDANO_SECURITY_PARAMETER",
    "BLOCK_STABILITY_MARGIN\t": "BLOCK_STABILITY_MARGIN",
    "DB_SYNC_POSTGRES_CONNECTION_STRING ": "DB_SYNC_POSTGRES_CONNECTION_STRING",
    "\u00a0DB_SYNC_POSTGRES_CONNECTION_STRING\u2003": "DB_SYNC_POSTGRES_CONNECTION_STRING",
    "block_stability_margin": "BLOCK_STABILITY_MARGIN",
    "Mc__First_Epoch_Number": "MC__FIRST_EPOCH_NUMBER",
    "MC__ FIRST_EPOCH_NUMBER": "MC__FIRST_EPOCH_NUMBER",
    " mc__\tfirst_epoch_number ": "MC__FIRST_EPOCH_NUMBER",
    "CARDANO_SECURITY_PARAMETER.depth": "CARDANO_SECURITY_PARAMETER",
    "MC__FIRST_EPOCH_NUMBER .x": "MC__FIRST_EPOCH_NUMBER",
    "PATH": "PATH",
    "MC_FIRST_EPOCH_NUMBER": "MC_FIRST_EPOCH_NUMBER",
}


@pytest.mark.parametrize("name, setting", NAMES_READ_AS.items(), ids=list(map(repr, NAMES_READ_AS)))
def test_a_name_is_read_as_the_most_forgiving_of_the_nodes_readers_takes_it(name, setting):
    assert capture_environ.reads_as(name) == setting


TWINS = [name for name, setting in NAMES_READ_AS.items() if name != setting and setting in capture_environ.CAPTURED]


@pytest.mark.parametrize("twin", TWINS, ids=list(map(repr, TWINS)))
def test_the_capture_keeps_a_name_the_node_reads_as_a_setting_spelled_as_the_process_has_it(twin):
    """Dropped, the node would run on a value the capture does not show: figment takes the later of two entries it
    reads as one setting."""
    exact = NAMES_READ_AS[twin]
    kept = capture_environ.captured(environ_block({exact: RUNNING_ENV[exact], twin: RUNNING_ENV[exact]}))
    assert kept == {exact: AUTHORITY_ENV[exact], twin: AUTHORITY_ENV[exact]}
    assert capture_environ.read(capture_block(kept)) == (kept, (NODE_PID, STARTED_TICKS))
    assert capture_environ.captured(environ_block({twin: RUNNING_ENV[exact]})) == {twin: AUTHORITY_ENV[exact]}


def test_a_connection_string_under_a_padded_name_is_reduced_like_the_exact_one():
    kept = capture_environ.captured(environ_block({
        "DB_SYNC_POSTGRES_CONNECTION_STRING": f"postgres://materios:{PASSWORD}@db-1.internal:5432/cexplorer",
        "DB_SYNC_POSTGRES_CONNECTION_STRING ": f"postgres://materios:{PASSWORD}@db-9.elsewhere:5432/cexplorer"}))
    assert kept == {"DB_SYNC_POSTGRES_CONNECTION_STRING": "db-1.internal:5432/cexplorer",
                    "DB_SYNC_POSTGRES_CONNECTION_STRING ": "db-9.elsewhere:5432/cexplorer"}


def test_the_capture_names_each_postgres_setting_and_shows_no_credential():
    process = dict(RUNNING_ENV, PGHOST="db-9.elsewhere", PGPORT="6432", PGDATABASE="other", PGUSER="materios",
                   PGPASSWORD=PASSWORD, PGPASSFILE="/run/secrets/pgpass", PGSSLKEY="/run/secrets/db.key",
                   PGSSLMODE="disable", PGSSLROOTCERT="/tmp/ca.pem", PGSSLCERT="/tmp/cert.pem", PGAPPNAME="x",
                   PGOPTIONS="-c search_path=fake")
    kept = capture_environ.captured(environ_block(process))
    assert {name: value for name, value in kept.items() if name.startswith("PG")} == {
        "PGHOST": "db-9.elsewhere", "PGPORT": "6432", "PGDATABASE": "other", "PGSSLMODE": "disable",
        "PGSSLROOTCERT": "/tmp/ca.pem", "PGSSLCERT": "/tmp/cert.pem", "PGAPPNAME": "x",
        "PGOPTIONS": "-c search_path=fake", "PGUSER": "<set>", "PGPASSWORD": "<set>", "PGPASSFILE": "<set>",
        "PGSSLKEY": "<set>"}
    written = capture_environ.written(kept, (NODE_PID, 77))
    assert PASSWORD.encode() not in written and b"/run/secrets" not in written and b"materios" not in written


@pytest.mark.parametrize("raw", [b"PGPASSWORD=" + PASSWORD.encode() + b"\0process=1 2\0",
                                 b"PGUSER=materios\0process=1 2\0"])
def test_a_capture_file_that_shows_a_credential_is_refused(raw):
    with pytest.raises(ValueError) as refused:
        capture_environ.read(raw)
    assert PASSWORD not in str(refused.value) and "materios" not in str(refused.value)


def test_a_setting_the_process_has_twice_is_refused():
    with pytest.raises(ValueError, match="^MAIN_CHAIN_FOLLOWER is set twice"):
        capture_environ.captured(b"MAIN_CHAIN_FOLLOWER=yaci\0MAIN_CHAIN_FOLLOWER=db-sync\0")


@pytest.mark.parametrize("raw", [
    b"MAIN_CHAIN_FOLLOWER=yaci\0process=1 2", b"MAIN_CHAIN_FOLLOWER\0process=1 2\0", b"\xff=1\0process=1 2\0",
    b"MAIN_CHAIN_FOLLOWER=yaci\0", b"", b"process=1 2\0MAIN_CHAIN_FOLLOWER=yaci\0",
    b"MAIN_CHAIN_FOLLOWER=yaci\0process=1 2\0process=1 2\0", b"MAIN_CHAIN_FOLLOWER=yaci\0process=1\0",
    b"MAIN_CHAIN_FOLLOWER=yaci\0process=one 2\0", b"MAIN_CHAIN_FOLLOWER=yaci\0process=1 -2\0",
    b"HOME=/root\0process=1 2\0", b"MAIN_CHAIN_FOLLOWER=yaci\0MAIN_CHAIN_FOLLOWER=yaci\0process=1 2\0"],
    ids=["no final NUL", "no =", "not UTF-8", "no process", "empty", "the process first", "two processes",
         "a process with no start", "a pid that is no number", "a negative start", "a setting it does not write",
         "a setting twice"])
def test_a_capture_that_is_not_what_the_tool_writes_is_refused(raw):
    with pytest.raises(ValueError):
        capture_environ.read(raw)


def test_the_process_a_capture_is_of_is_read_from_its_stat():
    assert capture_environ.process_of(process_stat(77, "materios node) x (", 99).encode()) == (99, 77)
    for stat in (b"", b"99 (materios-node", b"99 (materios-node) S 1"):
        with pytest.raises(ValueError):
            capture_environ.process_of(stat)


def test_the_capture_tool_runs_with_the_standard_library_alone(tmp_path):
    """A validator's machine needs python3 and this one file: no package of the preflight's."""
    done = subprocess.run([sys.executable, "-I", "-S", str(HERE / "capture_environ.py"), "--help"],
                          capture_output=True, text=True, cwd=tmp_path)
    assert done.returncode == 0 and "environ" in done.stdout, done.stderr


# When each process a test started began, in ticks after boot, read from its /proc/<pid>/stat before it is killed.
STARTED_BY = {}


def started(env: dict) -> subprocess.Popen:
    """A process started with `env`, once the kernel shows its environment: /proc/<pid>/environ reads empty until
    exec has set the new image's bounds, a moment after Popen returns."""
    process = subprocess.Popen(["sleep", "60"], env=env)
    deadline = time.monotonic() + 10
    while not Path(f"/proc/{process.pid}/environ").read_bytes() and time.monotonic() < deadline:
        time.sleep(0.01)
    STARTED_BY[process.pid] = int(Path(f"/proc/{process.pid}/stat").read_text().rpartition(")")[2].split()[19])
    return process


def test_the_capture_tool_writes_a_running_process_and_prints_only_names(tmp_path):
    process = started(RUNNING_ENV)
    try:
        out = tmp_path / "val-1.cmdline.environ"
        done = subprocess.run([sys.executable, "-I", "-S", str(HERE / "capture_environ.py"), str(process.pid),
                               str(out)], capture_output=True, text=True, cwd=tmp_path)
    finally:
        process.kill()
        process.wait()
    assert done.returncode == 0, done.stderr
    assert capture_environ.read(out.read_bytes()) == (AUTHORITY_ENV, (process.pid, STARTED_BY[process.pid]))
    assert done.stdout == (f"pid {process.pid}: {len(AUTHORITY_ENV)} settings written to {out}: "
                           f"{' '.join(sorted(AUTHORITY_ENV))}\n")
    for secret in (PASSWORD, SECRET_TOKEN, "db-1", "0x" + "ab" * 32):
        assert secret not in done.stdout + done.stderr


def test_the_capture_tool_writes_nothing_for_a_connection_string_it_cannot_reduce(tmp_path):
    env = dict(RUNNING_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING=f"host=db-1 password={PASSWORD}")
    process = started(env)
    try:
        out = tmp_path / "val-1.cmdline.environ"
        done = subprocess.run([sys.executable, "-I", "-S", str(HERE / "capture_environ.py"), str(process.pid),
                               str(out)], capture_output=True, text=True, cwd=tmp_path)
    finally:
        process.kill()
        process.wait()
    assert done.returncode == 1 and not out.exists()
    assert done.stderr.startswith("DB_SYNC_POSTGRES_CONNECTION_STRING is not a postgres:// URL")
    assert PASSWORD not in done.stdout + done.stderr


def environment_findings(tmp_path: Path, running: dict, env: dict = AUTHORITY_ENV, script: str | None = None):
    """Rule 8 on an authority whose manifest declares `env`, or a script, and whose node process was started with
    `running`, as the capture tool saves it next to its cmdline capture."""
    node = captured_node(tmp_path, env, script)
    Path(node["cmdline"] + ".environ").write_bytes(capture_block(running))
    return messages(lp.check_environment({"nodes": [node, {"name": "edge", "host": "edge", "authority": False}]}))


def captured_node(tmp_path: Path, env: dict = AUTHORITY_ENV, script: str | None = None) -> dict:
    """An authority with the captures rule 8 reads its environment by: its cmdline's path, which names where the
    environment capture is, and its process's stat."""
    node = dict(follower_node(env=env, script=script), cmdline=str(tmp_path / "val1.cmdline"),
                process_stat=str(tmp_path / "val1.stat"))
    Path(node["process_stat"]).write_text(process_stat())
    return node


def test_an_authority_whose_node_runs_with_the_settings_its_manifest_declares_passes(tmp_path):
    assert environment_findings(tmp_path, AUTHORITY_ENV) == []
    exports = "; ".join(f"export {name}={value}" for name, value in AUTHORITY_ENV.items())
    assert environment_findings(tmp_path, AUTHORITY_ENV, {}, f"{exports}; exec materios-node --validator") == []
    assert environment_findings(tmp_path, AUTHORITY_ENV, dict(AUTHORITY_ENV, RUST_LOG="info", TZ="UTC")) == []


MOCK_FOLLOWER = ("its node runs on the mock Cardano follower, or is one setting from it: whoever can write the mock's "
                 "registrations file chooses the committee data that node authors and verifies with")


@pytest.mark.parametrize("name, value", [
    ("USE_MAIN_CHAIN_FOLLOWER_MOCK", "true"), ("USE_MAIN_CHAIN_FOLLOWER_MOCK", "false"),
    ("USE_MAIN_CHAIN_FOLLOWER_MOCK", ""), ("MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE", "/srv/mock.json")])
def test_an_authority_whose_node_process_has_a_mock_follower_setting_is_refused(tmp_path, name, value):
    assert environment_findings(tmp_path, dict(AUTHORITY_ENV, **{name: value})) == [
        f"[8 node] authority val1: its node process was started with {name}: {MOCK_FOLLOWER}"]


DECLARED_APART = ("the preflight checked the settings its manifest declares, and its node runs with others")


@pytest.mark.parametrize("name, value", [("MC__FIRST_EPOCH_NUMBER", "209"), ("CARDANO_SECURITY_PARAMETER", "432"),
                                         ("MAIN_CHAIN_FOLLOWER", "yaci"), ("BLOCK_STABILITY_MARGIN", "10"),
                                         ("DB_SYNC_POSTGRES_CONNECTION_STRING", "db-9:5432/cexplorer"),
                                         ("SIDECHAIN_BLOCK_BENEFICIARY", "0x" + "cd" * 32)])
def test_an_authority_whose_node_runs_with_another_value_than_declared_is_refused(tmp_path, name, value):
    assert environment_findings(tmp_path, dict(AUTHORITY_ENV, **{name: value})) == [
        f"[8 node] authority val1: its node process was started with {name}={value}, and its manifest declares "
        f"{name}={AUTHORITY_ENV[name]}: {DECLARED_APART}"]


@pytest.mark.parametrize("name", sorted(AUTHORITY_ENV))
def test_an_authority_whose_node_runs_without_a_declared_setting_is_refused(tmp_path, name):
    running = {key: value for key, value in AUTHORITY_ENV.items() if key != name}
    assert environment_findings(tmp_path, running) == [
        f"[8 node] authority val1: its node process was started without {name}, which its manifest declares as "
        f"{name}={AUTHORITY_ENV[name]}: {DECLARED_APART}"]


@pytest.mark.parametrize("name, value", [("LD_PRELOAD", "/opt/hook.so"), ("MITHRIL_CLIENT_BIN", "/tmp/mithril"),
                                         ("MITHRIL_AGGREGATOR_ENDPOINT", "https://aggregator.example"),
                                         ("PGHOST", "db-9.elsewhere"), ("PGPORT", "6432"), ("PGDATABASE", "other"),
                                         ("PGOPTIONS", "-c search_path=fake"), ("PGSSLMODE", "disable"),
                                         ("PGSSLROOTCERT", "/tmp/ca.pem"), ("PGSSLCERT", "/tmp/cert.pem"),
                                         ("PGAPPNAME", "x"), ("PGUSER", "<set>"), ("PGPASSWORD", "<set>"),
                                         ("PGPASSFILE", "<set>"), ("PGSSLKEY", "<set>")])
def test_an_authority_whose_node_runs_with_a_setting_its_manifest_does_not_declare_is_refused(tmp_path, name, value):
    assert environment_findings(tmp_path, dict(AUTHORITY_ENV, **{name: value})) == [
        f"[8 node] authority val1: its node process was started with {name}={value}, which its manifest does not "
        f"declare: {DECLARED_APART}"]


def twin_refused(twin: str) -> str:
    return (f"[8 node] authority val1: its node process was started with a setting named {twin!r}, which is not the "
            f"exact name {NAMES_READ_AS[twin]}: the node's follower trims a setting's name, reads it "
            "whatever its case and takes the later of two it reads as one, so the node may run on that value and "
            "not on the declared one")


@pytest.mark.parametrize("twin", TWINS, ids=list(map(repr, TWINS)))
def test_an_authority_whose_node_process_has_a_setting_under_a_name_that_is_not_exact_is_refused(tmp_path, twin):
    """Beside the exact name, with the declared value under both, and in its place: either way the name refuses."""
    exact = NAMES_READ_AS[twin]
    assert environment_findings(tmp_path, dict(AUTHORITY_ENV, **{twin: AUTHORITY_ENV[exact]})) == [twin_refused(twin)]
    alone = {name: value for name, value in AUTHORITY_ENV.items() if name != exact}
    assert environment_findings(tmp_path, dict(alone, **{twin: AUTHORITY_ENV[exact]})) == [
        twin_refused(twin),
        f"[8 node] authority val1: its node process was started without {exact}, which its manifest declares as "
        f"{exact}={AUTHORITY_ENV[exact]}: {DECLARED_APART}"]


def test_the_value_under_a_name_that_is_not_exact_is_not_shown(tmp_path):
    found = environment_findings(tmp_path, dict(AUTHORITY_ENV, **{"DB_SYNC_POSTGRES_CONNECTION_STRING ": "db-9:1/x"}))
    assert found == [twin_refused("DB_SYNC_POSTGRES_CONNECTION_STRING ")] and "db-9" not in found[0]


def test_an_environment_capture_of_another_process_than_its_stat_capture_is_refused(tmp_path):
    """A capture left from before a restart, or taken of another process: the settings are not this node's."""
    node = captured_node(tmp_path)
    for pid, ticks, said in ((NODE_PID, STARTED_TICKS - 1, f"pid {NODE_PID}, started at tick {STARTED_TICKS - 1}"),
                             (NODE_PID + 1, STARTED_TICKS, f"pid {NODE_PID + 1}, started at tick {STARTED_TICKS}")):
        Path(node["cmdline"] + ".environ").write_bytes(capture_block(AUTHORITY_ENV, pid, ticks))
        with pytest.raises(lp.InputError) as refused:
            lp.check_environment({"nodes": [node]})
        assert str(refused.value) == (
            f"authority val1: environ {node['cmdline']}.environ was taken of {said}, and its process_stat capture is "
            f"of pid {NODE_PID}, started at tick {STARTED_TICKS}: the settings are another process's, as a capture "
            "left from before a restart is; take both of the node process that runs now")
    Path(node["cmdline"] + ".environ").write_bytes(capture_block(AUTHORITY_ENV))
    assert lp.check_environment({"nodes": [node]}) == []


def test_an_authority_with_no_stat_capture_cannot_tie_its_environment_to_a_process(tmp_path):
    node = captured_node(tmp_path)
    Path(node["cmdline"] + ".environ").write_bytes(capture_block(AUTHORITY_ENV))
    del node["process_stat"]
    with pytest.raises(lp.InputError, match="authority val1: give a copy of its node process's /proc/<pid>/stat"):
        lp.check_environment({"nodes": [node]})


CONNECTION_URL = f"postgres://materios:{PASSWORD}@db-1.internal:5432/cexplorer"


@pytest.mark.parametrize("running", [AUTHORITY_ENV,
                                     dict(AUTHORITY_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING="db-9:5432/cexplorer"),
                                     {name: value for name, value in AUTHORITY_ENV.items()
                                      if name != "DB_SYNC_POSTGRES_CONNECTION_STRING"}],
                         ids=["the same database", "another database", "none"])
def test_a_connection_string_the_manifest_declares_is_never_shown(tmp_path, running):
    """A manifest that wrongly holds the URL, password and all: rule 9 refuses it, and rule 8's line on the
    difference names the setting and shows neither side's value unless it is a reduced one."""
    found = environment_findings(tmp_path, running,
                                 dict(AUTHORITY_ENV, DB_SYNC_POSTGRES_CONNECTION_STRING=CONNECTION_URL))
    assert len(found) == 1 and "DB_SYNC_POSTGRES_CONNECTION_STRING" in found[0]
    assert PASSWORD not in found[0] and "materios:" not in found[0] and "postgres://" not in found[0]


def test_cli_never_shows_a_connection_string_a_manifest_wrongly_holds(clean, capsys):
    for node in clean.launch["nodes"]:
        if node["authority"]:
            clean.environ[node["name"]] = dict(node["env"])
            node["env"]["DB_SYNC_POSTGRES_CONNECTION_STRING"] = CONNECTION_URL
    code, out = clean.run(capsys)
    assert code == 1 and "[9 committee] authority val0 gives DB_SYNC_POSTGRES_CONNECTION_STRING in another form" in out
    assert "[8 node] authority val0: its node process was started with DB_SYNC_POSTGRES_CONNECTION_STRING" in out
    assert PASSWORD not in out and "materios:" not in out


def test_every_setting_an_authority_runs_apart_from_its_manifest_is_named(tmp_path):
    running = dict(AUTHORITY_ENV, USE_MAIN_CHAIN_FOLLOWER_MOCK="true", MC__FIRST_EPOCH_NUMBER="209")
    del running["SIDECHAIN_BLOCK_BENEFICIARY"]
    assert len(environment_findings(tmp_path, running)) == 3


def test_an_authority_with_no_environment_capture_is_an_input_error_that_says_how_to_take_it(tmp_path):
    node = captured_node(tmp_path)
    with pytest.raises(lp.InputError) as refused:
        lp.check_environment({"nodes": [node]})
    assert str(refused.value) == (
        f"authority val1: cannot read environ {tmp_path / 'val1.cmdline.environ'}: No such file or directory; take it "
        "on its machine with `python3 capture_environ.py <pid> <its cmdline capture>.environ`, which writes the "
        "settings the preflight reads and no password")


def test_an_environment_capture_that_is_no_capture_is_an_input_error(tmp_path):
    node = captured_node(tmp_path)
    Path(node["cmdline"] + ".environ").write_bytes(b"PATH=/usr/bin")
    with pytest.raises(lp.InputError, match="authority val1: environ .* is not what capture_environ.py writes"):
        lp.check_environment({"nodes": [node]})


def test_a_raw_copy_of_the_environment_is_refused_as_a_capture(tmp_path):
    """`cat /proc/<pid>/environ` holds every setting, the database password among them: the preflight reads only what
    the capture tool writes."""
    node = captured_node(tmp_path)
    Path(node["cmdline"] + ".environ").write_bytes(environ_block(RUNNING_ENV))
    with pytest.raises(lp.InputError) as refused:
        lp.check_environment({"nodes": [node]})
    assert "is not what capture_environ.py writes" in str(refused.value) and PASSWORD not in str(refused.value)


# The rehearsal's PASS was given to four authorities on the mock follower: their manifest left the setting out.
def test_cli_refuses_an_authority_running_the_mock_follower_its_manifest_leaves_out(clean, capsys):
    clean.environ["val1"] = dict(clean.launch["nodes"][1]["env"], USE_MAIN_CHAIN_FOLLOWER_MOCK="true",
                                 MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE="/srv/rehearsal/registrations.json")
    code, out = clean.run(capsys)
    assert (code, out.splitlines()[1:]) == (1, [
        f"  [8 node] authority val1: its node process was started with {name}: {MOCK_FOLLOWER}"
        for name in ("MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE", "USE_MAIN_CHAIN_FOLLOWER_MOCK")]), out


def test_cli_refuses_an_authority_whose_database_is_not_the_declared_one(clean, capsys):
    clean.environ["val3"] = dict(clean.launch["nodes"][3]["env"],
                                 DB_SYNC_POSTGRES_CONNECTION_STRING="db-elsewhere:5432/cexplorer")
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(
        out, "[8 node] authority val3: its node process was started with DB_SYNC_POSTGRES_CONNECTION_STRING="
             "db-elsewhere:5432/cexplorer, and its manifest declares DB_SYNC_POSTGRES_CONNECTION_STRING="
             f"db-1.internal:5432/cexplorer: {DECLARED_APART}"), out


# ---------------------------------------------------------------------------
# A verdict before any node runs, and every input error in one run
# ---------------------------------------------------------------------------

GENESIS_PASS = "MAINNET LAUNCH PREFLIGHT (genesis stage): PASS"
NOT_THE_GATE = ("This is not the launch gate: run check without --stage once every authority's node runs, and "
                "announce the genesis hash only after it passes.")
NOT_RUN_BEFORE_START = [
    "[3 rpc] what each public RPC URL serves, probed live",
    "[3 rpc] the argv each authority's node process runs with: its listeners were read from its manifest argv",
    "[8 node] the genesis and chain each authority's running node serves, the binary and chain spec file it runs, "
    "and when its --chain path last changed",
    "[8 node] the environment each authority's node process was started with: a mock follower, or a setting other "
    "than its manifest declares",
]
NOT_RUN_WITHOUT_KUPO = [
    "[1 dev-keys] [9 committee] the D-parameter and the permissioned candidates on Cardano: their keys, the "
    "committee the runtime draws from them, and their age",
    "[3 rpc] a Cardano permissioned candidate with no authority node",
    "[4 supply] the genesis lock on Cardano: the cMATRA it holds, who can spend it and the genesis its datum binds",
]


def genesis_stage(clean, capsys, kupo=True, binaries=None, launch=None) -> tuple[int, str]:
    """`sign`, then `check --stage genesis`, with every keyholder's proof in and no authority's node running: no
    capture of any is on disk."""
    spec_path = clean.prepare()
    for node in clean.launch["nodes"]:
        for field in ("cmdline", *lp.CAPTURES):
            if node["authority"] and field != "exe" and field in node:
                Path(node[field]).unlink(missing_ok=True)
        if "cmdline" in node:
            Path(node["cmdline"] + ".environ").unlink(missing_ok=True)
    operator = clean.tmp_path / "operator-keys.json"
    operator.write_text(json.dumps({"keys": []}))
    seed, signed, launch_path = (clean.tmp_path / name for name in ("launch.key", "signed.json", "launch.json"))
    seed.write_text("0x" + clean.launch_key.encode().hex() + "\n")
    launch_path.write_text(json.dumps(launch or prove(clean.launch, lp.load_spec(str(spec_path)))))
    assert lp.main(["sign", "--spec", str(spec_path), "--launch", str(launch_path), "--key", str(seed), "--out",
                    str(signed)]) == 0
    capsys.readouterr()
    binaries = [clean.node_exe] if binaries is None else binaries
    code = lp.main(["check", "--stage", "genesis", "--spec", str(spec_path), "--launch", str(launch_path),
                    "--signed-manifest", str(signed), "--subwasm", subwasm(), "--extra-well-known", str(operator),
                    *(["--kupo", clean.kupo.url] if kupo else []),
                    *(word for binary in binaries for word in ("--node-binary", str(binary)))])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_cli_the_launch_gate_before_any_node_runs_names_every_capture_it_lacks(clean, capsys):
    """The rehearsal's run before the nodes started stopped at the first authority's cmdline and said nothing else."""
    spec_path = clean.prepare()
    missing = []
    for node in clean.launch["nodes"]:
        if node["authority"]:
            for field in ("cmdline", "chain_spec", "served_genesis", *SERVED_IDENTITY, "process_stat", "system_stat",
                          "chain_spec_stat"):
                Path(node[field]).unlink()
                missing.append(f"authority {node['name']}: cannot read {field} {node[field]}: No such file or "
                               "directory")
            Path(node["cmdline"] + ".environ").unlink()
            missing.append(f"authority {node['name']}: cannot read environ {node['cmdline']}.environ: ")
    code, out = run_cli(clean.tmp_path, spec_path, prove(clean.launch, lp.load_spec(str(spec_path))), capsys,
                        clean.kupo.url, clean.launch_key)
    assert code == 2 and "PASS" not in out
    refused = [line for line in out.splitlines() if line.startswith("MAINNET LAUNCH PREFLIGHT: REFUSE (input) ")]
    assert len(refused) == len(missing) == 40
    assert all(any(reason in line for line in refused) for reason in missing), out
    assert "check --stage genesis" in out


def test_cli_the_genesis_stage_passes_a_clean_launch_before_any_node_runs(clean, capsys):
    code, out = genesis_stage(clean, capsys)
    assert code == 0, out
    assert out.splitlines() == [GENESIS_PASS, *("  not run: " + rule for rule in NOT_RUN_BEFORE_START), NOT_THE_GATE]
    assert PASS not in out


def test_cli_the_genesis_stage_without_a_kupo_names_the_cardano_rules_it_did_not_run(clean, capsys):
    code, out = genesis_stage(clean, capsys, kupo=False)
    assert code == 0, out
    assert out.splitlines() == [GENESIS_PASS, *("  not run: " + rule
                                                for rule in NOT_RUN_BEFORE_START + NOT_RUN_WITHOUT_KUPO), NOT_THE_GATE]


def test_cli_the_genesis_stage_runs_each_pinned_binarys_build_of_the_manifest(clean, capsys):
    log = clean.tmp_path / "calls.jsonl"
    exe = fake_node(clean.tmp_path, log=str(log))
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node.update(exe=str(clean.tmp_path / f"{node['name']}.exe-capture-to-come"), exe_sha256=sha256_pin(exe))
    code, out = genesis_stage(clean, capsys, binaries=[exe])
    assert code == 0, out
    calls = node_calls(log)
    assert sorted(call["argv"][1] for call in calls) == ["build-spec", "chain-id", "export-blocks", "export-blocks"]
    assert [call["manifest_sha256"] for call in calls if call["argv"][1] == "build-spec"] == [hashlib.sha256(
        (clean.tmp_path / "launch.json").read_bytes()).hexdigest()]
    spec_sha = hashlib.sha256((clean.tmp_path / "clean-raw.json").read_bytes()).hexdigest()
    assert [call["chain_sha256"] for call in calls if call["argv"][1] != "build-spec"] == [False, spec_sha, spec_sha]


def test_cli_the_genesis_stage_refuses_a_spec_the_pinned_binary_does_not_build(clean, capsys):
    clean.node_builds_this()
    del clean.spec.storage[lp.storage_key("Grandpa", "CurrentSetId")]
    code, out = genesis_stage(clean, capsys)
    assert code == 1, out
    assert out.splitlines()[:2] == [
        "MAINNET LAUNCH PREFLIGHT (genesis stage): REFUSE (1 reasons)",
        f"  {NOT_THE_BUILD}genesis storage differs at 1 key: Grandpa.CurrentSetId, which only the node's build sets"]
    assert out.splitlines()[2:] == [*("  not run: " + rule for rule in NOT_RUN_BEFORE_START), NOT_THE_GATE]


def test_cli_the_genesis_stage_needs_each_pinned_binary(clean, capsys):
    other = fake_node(clean.tmp_path, log=str(clean.tmp_path / "unpinned.jsonl"))
    code, out = genesis_stage(clean, capsys, binaries=[other])
    pin = clean.launch["nodes"][0]["exe_sha256"]
    assert (code, out.splitlines()) == (2, [
        f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) authority {name} pins exe_sha256 {pin}, and no --node-binary given "
        "is that file: the genesis stage runs each pinned binary's build-spec on the launch manifest, so give the "
        "release binary every validator will run" for name in ("val0", "val1", "val2", "val3")]), out


def test_cli_the_genesis_stage_refuses_what_the_launch_gate_refuses_of_the_manifest_proofs_and_signature(clean, capsys):
    spec_path = clean.prepare()
    launch = prove(clean.launch, lp.load_spec(str(spec_path)))
    del launch["roles"]["sudo"][0]["members"][2]["pop"]
    del launch["nodes"][1]["env"]["SIDECHAIN_BLOCK_BENEFICIARY"]
    launch["nodes"][3]["argv"] = [*launch["nodes"][3]["argv"][:-1], "unsafe", "--unsafe-rpc-external"]
    code, out = genesis_stage(clean, capsys, launch=launch)
    assert code == 1, out
    assert out.splitlines()[:4] == [
        "MAINNET LAUNCH PREFLIGHT (genesis stage): REFUSE (3 reasons)",
        "  " + no_pop("roles.sudo[0].members[2]", "sudo", "0 2"),
        "  " + NO_BENEFICIARY,
        "  [3 rpc] authority val3 serves unsafe RPC methods on an external listener"], out


def test_cli_the_genesis_stage_checks_cardano_where_a_kupo_is_given(clean, capsys):
    clean.lock_output = kupo_output(assets={lp.CMATRA_UNIT: 1})
    code, out = genesis_stage(clean, capsys)
    assert code == 1 and "[4 supply] Materios issues " in out.splitlines()[1], out


def test_cli_the_genesis_stage_reads_no_capture(clean, capsys):
    for node in clean.launch["nodes"]:
        if node["authority"]:
            for field in ("cmdline", *lp.CAPTURES):
                del node[field]
    code, out = genesis_stage(clean, capsys)
    assert (code, out.splitlines()[0]) == (0, GENESIS_PASS), out


@pytest.mark.parametrize("words, error", [
    (["--node-binary", "materios-node"], "--node-binary is read in the genesis stage only: the launch gate runs each "
                                         "authority's exe capture, the binary its node process runs"),
    ([], None)])
def test_cli_the_launch_gate_takes_no_binary_and_needs_a_kupo(clean, capsys, words, error):
    spec_path = clean.prepare()
    operator = clean.tmp_path / "operator-keys.json"
    operator.write_text(json.dumps({"keys": []}))
    launch_path = clean.tmp_path / "launch.json"
    launch_path.write_text(json.dumps(clean.launch))
    code = lp.main(["check", "--spec", str(spec_path), "--launch", str(launch_path), "--signed-manifest",
                    str(clean.tmp_path / "signed.json"), "--extra-well-known", str(operator),
                    *(["--kupo", clean.kupo.url] if words else []), *words])
    out = capsys.readouterr()
    error = error or ("the launch gate needs --kupo, a Kupo on Cardano mainnet: only check --stage genesis runs "
                      "without one, and says which rules it did not run")
    assert (code, out.out + out.err) == (2, f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) {error}\n")


def test_every_unreadable_part_of_a_launch_manifest_is_named_in_one_run():
    launch = {"roles": {"oracle": "5Grw", "treasury": []}, "economics": {"fee_bufer": 1}, "supply": VALID_LOCK,
              "slots_per_epoch": "600",
              "nodes": [{"name": "val1", "host": "val1", "authority": True, "env": {"LD_PRELOAD": "/x.so"}},
                        {"name": "edge", "host": "edge", "authority": False, "exe": "edge.exe"},
                        dict(authority(["materios-node", "--validator"]), env={"USE_MAIN_CHAIN_FOLLOWER_MOCK": "1"})],
              "public_rpc": ["ftp://rpc.example.org"]}
    with pytest.raises(lp.InputError) as refused:
        lp.validate_launch(launch)
    assert [str(error).split(":")[0].split(",")[0] for error in refused.value.errors] == [
        "roles.oracle must be a list of public keys",
        "roles.treasury is not a role a mainnet launch knows",
        "unknown economics field fee_bufer",
        "slots_per_epoch must be a u32",
        "node val1",
        "nodes[1] exe is read for an authority only",
        "node val1",
        "public_rpc[0] must be an http"]
    assert str(refused.value) == "\n".join(map(str, refused.value.errors))


def test_one_unreadable_part_is_the_error_it_always_was():
    with pytest.raises(lp.InputError) as refused:
        lp.validate_launch({"roles": {}, "supply": VALID_LOCK, "slots_per_epoch": "600"})
    assert type(refused.value) is lp.InputError and str(refused.value).startswith("slots_per_epoch must be a u32")


def test_cli_names_every_unreadable_part_of_the_manifest_in_one_run(clean, capsys):
    clean.launch["nodes"][0]["env"]["GCONV_PATH"] = "/tmp/gconv"
    clean.launch["nodes"][2]["argv"].append("--not-an-option")
    clean.launch["public_rpc"].append("ftp://rpc.example.org")
    signing_code, code, out = sign_and_check(clean.tmp_path, clean.prepare(), clean.launch, capsys, clean.kupo.url,
                                             clean.launch_key)
    assert (signing_code, code) == (2, 2)
    assert out.splitlines() == [
        "MAINNET LAUNCH PREFLIGHT: REFUSE (input) node val0: sets GCONV_PATH, which is not a setting an authority may "
        "set (logging, TZ and the node's Cardano follower settings); the preflight cannot read what it changes",
        "MAINNET LAUNCH PREFLIGHT: REFUSE (input) authority val2: gives --not-an-option, an option the preflight does "
        "not know, so it cannot tell whether it changes the genesis the node builds",
        "MAINNET LAUNCH PREFLIGHT: REFUSE (input) public_rpc[1] must be an http, https, ws or wss URL"]


def test_cli_names_the_input_errors_of_separate_rules_and_the_reasons_of_the_rest_in_one_run(clean, capsys):
    """A stored number of another width stops rule 2 and an answer that is no JSON-RPC stops rule 8; rule 9 still
    refuses the authority with no beneficiary."""
    put(clean.spec, "OrinqReceipts", "EraCapBase", b"\x01")
    clean.node_builds_this()
    del clean.launch["nodes"][2]["env"]["SIDECHAIN_BLOCK_BENEFICIARY"]
    spec_path = clean.prepare()
    Path(clean.launch["nodes"][0]["served_chain"]).write_text("not json")
    code, out = run_cli(clean.tmp_path, spec_path, prove(clean.launch, lp.load_spec(str(spec_path))), capsys,
                        clean.kupo.url, clean.launch_key)
    assert code == 2 and "PASS" not in out
    assert "  " + NO_BENEFICIARY.replace("val1", "val2") in out.splitlines()
    refused = [line for line in out.splitlines() if line.startswith("MAINNET LAUNCH PREFLIGHT: REFUSE (input) ")]
    assert len(refused) == 2 and "OrinqReceipts.EraCapBase" in refused[0] and "served_chain" in refused[1], out


# ---------------------------------------------------------------------------
# The launch key: minted offline, pinned by review
# ---------------------------------------------------------------------------

def launch_key_cli(capsys, *words: str) -> tuple[int, str, str]:
    code = lp.main(["launch-key", *words])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_a_minted_launch_key_is_a_seed_only_its_owner_reads_and_prints_only_its_public_key(tmp_path, capsys):
    path = tmp_path / "launch.key"
    code, out, err = launch_key_cli(capsys, "new", "--out", str(path))
    assert code == 0 and err == ""
    assert path.stat().st_mode & 0o777 == 0o600
    seed = path.read_text()
    assert re.fullmatch(r"0x[0-9a-f]{64}\n", seed)
    public = bytes(signing.SigningKey(bytes.fromhex(seed[2:-1])).verify_key)
    assert out == f"0x{public.hex()}\n"
    assert seed.strip() not in out and seed[2:-1] not in out


def test_minting_two_launch_keys_gives_two_keys(tmp_path, capsys):
    printed = [launch_key_cli(capsys, "new", "--out", str(tmp_path / f"{i}.key"))[1] for i in range(2)]
    assert printed[0] != printed[1]


def test_minting_a_launch_key_overwrites_no_file(tmp_path, capsys):
    path = tmp_path / "launch.key"
    path.write_text("0x" + "11" * 32 + "\n")
    code, out, err = launch_key_cli(capsys, "new", "--out", str(path))
    assert (code, out) == (2, "") and "File exists" in err and "11" * 32 not in err
    assert path.read_text() == "0x" + "11" * 32 + "\n"


def test_the_public_key_of_a_launch_key_file_is_printed_without_its_seed(tmp_path, capsys):
    key = signing.SigningKey.generate()
    path = tmp_path / "launch.key"
    path.write_text("0x" + key.encode().hex() + "\n")
    assert launch_key_cli(capsys, "public", "--key", str(path)) == (0, f"0x{pub(key).hex()}\n", "")


@pytest.mark.parametrize("text", ["0x" + "11" * 31, "11" * 32, "0x" + "zz" * 32, ""])
def test_a_launch_key_file_that_holds_no_seed_is_refused_without_echoing_it(tmp_path, capsys, text):
    path = tmp_path / "launch.key"
    path.write_text(text)
    code, out, err = launch_key_cli(capsys, "public", "--key", str(path))
    assert (code, out) == (2, "")
    assert err.startswith(f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) cannot load the launch signing key from {path}")
    assert not text or text[2:] not in err


def test_a_minted_key_signs_a_manifest_that_verifies_under_the_key_it_printed(clean, tmp_path, capsys, monkeypatch):
    path = tmp_path / "minted.key"
    public = launch_key_cli(capsys, "new", "--out", str(path))[1].strip()
    pin_launch_keys(monkeypatch, tmp_path, bytes.fromhex(public[2:]))
    clean.launch_key = signing.SigningKey(bytes.fromhex(path.read_text()[2:-1]))
    code, out = clean.run(capsys)
    assert (code, out.splitlines()) == (0, [PASS, f"  signed by launch key {public}, pinned in "
                                                  f"{tmp_path / 'launch_keys.json'}"]), out


def test_cli_a_pass_names_the_pinned_launch_key_that_signed(clean, capsys):
    code, out = clean.run(capsys)
    assert (code, out.splitlines()) == (0, [PASS, f"  signed by launch key 0x{pub(clean.launch_key).hex()}, pinned in "
                                                  f"{clean.tmp_path / 'launch_keys.json'}"])


# ---------------------------------------------------------------------------
# Rule 8: why a --chain path under a busy directory refuses
# ---------------------------------------------------------------------------

def test_a_refused_chain_path_says_what_moves_a_directorys_ctime(clean, capsys):
    step = lookup(authority_chain(clean.tmp_path))[0]
    clean.changed["val1"] = {step: STARTED + 30}
    code, out = clean.run(capsys)
    assert code == 1 and only_reason(out, changed_after_start(step, STARTED + 30).replace("val0", "val1")), out


# ---------------------------------------------------------------------------
# A setting's name, as the node's readers take it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("twin", TWINS, ids=list(map(repr, TWINS)))
def test_a_manifest_that_declares_a_setting_under_a_name_that_is_not_exact_is_refused(twin):
    exact = NAMES_READ_AS[twin]
    node = follower_node(env=dict(AUTHORITY_ENV, **{twin: AUTHORITY_ENV[exact]}))
    with pytest.raises(lp.InputError) as refused:
        lp.validate_node(node, "nodes[0]")
    assert str(refused.value) == (
        f"node val1: sets a setting named {twin!r}, which is not the exact name {exact}: the node's follower trims a "
        "setting's name, reads it whatever its case and takes the later of two it reads as one, so declare each "
        "setting under its exact name alone")


@pytest.mark.parametrize("twin", ["use_main_chain_follower_mock", "LD_PRELOAD ", " pghost"])
def test_a_node_that_is_no_authority_may_not_declare_such_a_name_either(twin):
    node = {"name": "edge", "host": "edge", "authority": False, "env": {twin: "x"}}
    with pytest.raises(lp.InputError, match=f"node edge: sets a setting named {twin!r}, which is not the exact name"):
        lp.validate_node(node, "nodes[0]")


def node_process_captures(clean, name: str, process: subprocess.Popen) -> None:
    """Take an authority's environment, stat and machine captures from a process of this host, as its operator
    takes them from its node: the tool for the first, a copy of /proc for the others."""
    node = next(node for node in clean.launch["nodes"] if node["name"] == name)
    Path(node["process_stat"]).write_bytes(Path(f"/proc/{process.pid}/stat").read_bytes())
    Path(node["system_stat"]).write_bytes(Path("/proc/stat").read_bytes())
    done = subprocess.run([sys.executable, "-I", "-S", str(HERE / "capture_environ.py"), str(process.pid),
                           node["cmdline"] + ".environ"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def gate_on_a_process(clean, capsys, extra: dict) -> tuple[int, str]:
    """The launch gate on the clean launch, its first authority's process captures taken from a process of this host
    started with the settings its manifest declares, the database as the URL the node is given, and `extra`."""
    spec_path = clean.prepare()
    node = clean.launch["nodes"][0]
    process = started(dict(node["env"], DB_SYNC_POSTGRES_CONNECTION_STRING=CONNECTION_URL, **extra))
    try:
        node_process_captures(clean, node["name"], process)
    finally:
        process.kill()
        process.wait()
    return run_cli(clean.tmp_path, spec_path, prove(clean.launch, lp.load_spec(str(spec_path))), capsys,
                   clean.kupo.url, clean.launch_key)


def test_cli_passes_an_authority_whose_process_was_started_with_what_its_manifest_declares(clean, capsys):
    code, out = gate_on_a_process(clean, capsys, {})
    assert (code, out.splitlines()[0]) == (0, PASS), out


def test_cli_refuses_an_authority_whose_process_has_another_value_under_the_exact_name(clean, capsys):
    code, out = gate_on_a_process(clean, capsys, {"MC__FIRST_EPOCH_NUMBER": "1"})
    assert code == 1 and "started with MC__FIRST_EPOCH_NUMBER=1, and its manifest declares" in out, out


# The node read the padded entry and the gate read the exact one: a database, an epoch layout, a security parameter
# and a stability margin the manifest never showed.
@pytest.mark.parametrize("extra", [
    {"MC__FIRST_EPOCH_NUMBER ": "1"},
    {"DB_SYNC_POSTGRES_CONNECTION_STRING ": f"postgres://materios:{PASSWORD}@attacker.example:5432/fake"},
    {" CARDANO_SECURITY_PARAMETER": "5", "BLOCK_STABILITY_MARGIN\t": "9"},
    {"MC__ FIRST_EPOCH_NUMBER": "1"}, {"mc__first_epoch_number": "1"}, {"PGOPTIONS": "-c search_path=fake"},
], ids=["a padded epoch number", "a padded database", "a padded security parameter and margin",
        "a space after the MC__ prefix", "a lowercase epoch number", "session options for the database"])
def test_cli_refuses_an_authority_whose_process_has_a_setting_the_node_reads_and_the_manifest_does_not_show(
        clean, capsys, extra):
    code, out = gate_on_a_process(clean, capsys, extra)
    refused = out.splitlines()[1:]
    assert code == 1 and len(refused) == len(extra), out
    for name, line in zip(sorted(extra), refused):
        said = (f"was started with {name}={extra[name]}, which its manifest does not declare"
                if capture_environ.reads_as(name) == name else
                f"was started with a setting named {name!r}, which is not the exact name")
        assert line.startswith("  [8 node] authority val0: its node process ") and said in line, out
    assert PASSWORD not in out and "attacker.example" not in out


# ---------------------------------------------------------------------------
# What the genesis stage runs is what the launch gate runs, less what reads a running node
# ---------------------------------------------------------------------------

def pinned_to_a_node(clean, **knobs) -> Path:
    """Pin every authority of the clean launch to a stand-in node with these knobs, and return its call log."""
    log = clean.tmp_path / "pinned-calls.jsonl"
    exe = fake_node(clean.tmp_path, log=str(log), **knobs)
    clean.node_exe = exe
    for node in clean.launch["nodes"]:
        if node["authority"]:
            node.update(exe=str(exe), exe_sha256=sha256_pin(exe))
    return log


def reasons(out: str) -> list[str]:
    return [line for line in out.splitlines() if line.startswith("  [")]


# What a pinned binary shows of the checked spec with no node running: the genesis it builds from it, the chain ids
# its runtime holds at block one, the Cardano ids it reads, and the chain its argv names.
BINARY_ALONE = {
    "a node that builds another genesis": (lambda clean: pinned_to_a_node(clean, tamper=True),
                                           "its node builds genesis 0x"),
    "a runtime chain id that is not the genesis": (
        lambda clean: pinned_to_a_node(clean, chain_ids={"Oracle.MateriosChainId": [7] * 32}),
        "the spec's runtime holds Oracle.MateriosChainId 0x"),
    "a runtime that reads other Cardano ids": (
        lambda clean: pinned_to_a_node(clean, cardano_ids={"network_magic": 1, "mainchain_genesis_hash": [0] * 32,
                                                           "aegis_policy_v1_script_hash": [0] * 28}),
        "its node's chain-id reads IntentSettlement.CardanoIds as network magic 1"),
    "a chain built into the node": (lambda clean: with_node_argv(clean, ["--chain", "local"]),
                                    "--chain 'local' builds genesis 0x"),
    "no chain": (lambda clean: with_node_argv(clean, []), "gives no --chain"),
}


@pytest.mark.parametrize("arrange, reason", BINARY_ALONE.values(), ids=BINARY_ALONE)
def test_cli_the_genesis_stage_refuses_whatever_the_launch_gate_refuses_of_the_binary_and_the_spec_alone(
        clean, capsys, arrange, reason):
    arrange(clean)
    gate_code, gate_out = clean.run(capsys)
    stage_code, stage_out = genesis_stage(clean, capsys)
    assert gate_code == 1 and all("[8 node]" in line and reason in line for line in reasons(gate_out)), gate_out
    assert (stage_code, reasons(stage_out)) == (1, reasons(gate_out)), stage_out


# Defects of a launch that no capture shows, one from each rule the stage runs.
ANY_RULE = {
    "1 dev-keys": lambda clean: clean.launch["roles"].update(anchor_signer=[ss58(ALICE)]),
    "2 rewards": lambda clean: clean.launch["economics"].update(era_cap_baseline_attestor_count=31),
    "3 rpc": lambda clean: clean.launch["nodes"][0].update(
        argv=[*clean.launch["nodes"][0]["argv"][:-1], "unsafe", "--unsafe-rpc-external"]),
    "4 supply": lambda clean: clean.launch["dust"]["dust_pool"].update(
        {name: amount + 1 for name, amount in clean.launch["dust"]["dust_pool"].items()}),
    "6 checkpoint": lambda clean: clean.spec.doc.update(codeSubstitutes={"1": "0x00"}),
    "7 timelock": lambda clean: put(clean.spec, "RootTimelock", "Delays", delays(*TESTNET_DELAYS)),
    "9 committee": lambda clean: clean.launch["nodes"][2]["env"].pop("SIDECHAIN_BLOCK_BENEFICIARY"),
    "11 settlement": lambda clean: clean.launch.update(settlement=dict(BOUND_AFTER_GENESIS)),
    "12 dust": lambda clean: put(clean.spec, "Motra", "Params", bytes(108)),
}


@pytest.mark.parametrize("rule", ANY_RULE)
def test_cli_the_genesis_stage_gives_the_launch_gates_reasons_for_a_defect_no_capture_shows(clean, capsys, rule):
    ANY_RULE[rule](clean)
    clean.node_builds_this()
    gate_code, gate_out = clean.run(capsys)
    stage_code, stage_out = genesis_stage(clean, capsys)
    assert gate_code == 1 and any(f"[{rule}]" in line for line in reasons(gate_out)), gate_out
    assert (stage_code, reasons(stage_out)) == (1, reasons(gate_out)), stage_out


def functions_of_the_preflight() -> dict[str, ast.FunctionDef]:
    tree = ast.parse((HERE / "launch_preflight.py").read_text())
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def names_used(node: ast.AST) -> set[str]:
    """Every name a piece of code refers to: what it calls, and what it hands on to be called. A function is read by
    its body: what a parameter defaults to is the caller's to replace."""
    parts = node.body if isinstance(node, ast.FunctionDef) else [node]
    return {inner.id for part in parts for inner in ast.walk(part) if isinstance(inner, ast.Name)}


def reaches(start: set[str], functions: dict[str, ast.FunctionDef]) -> set[str]:
    """`start` and every function of the preflight those functions refer to, at any depth."""
    seen, queue = set(), [name for name in start if name in functions]
    while queue:
        name = queue.pop()
        if name not in seen:
            seen.add(name)
            queue += [used for used in names_used(functions[name]) if used in functions]
    return seen


def findings_made(function: ast.FunctionDef) -> int:
    return sum(isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Finding"
               for node in ast.walk(function))


def steps_of_a_run() -> list[tuple[str | None, set[str]]]:
    """(what the step needs that a run may lack, the functions it calls) for each step run_checks lists."""
    run_checks = functions_of_the_preflight()["run_checks"]
    steps = next(node.value for node in ast.walk(run_checks) if isinstance(node, ast.Assign)
                 and getattr(node.targets[0], "id", None) == "steps")
    listed = []
    for step in steps.elts:
        needs, check = step.elts
        listed.append((getattr(lp, needs.id) if isinstance(needs, ast.Name) else needs.value, names_used(check)))
    return listed


# The readers through which a rule reads a running node: its captures but the binary, which the genesis stage is
# given, and the live probe of a public URL.
READS_A_RUNNING_NODE = {"read_capture", "running_argv", "running_environ", "rpc_answer"}
# Each function that makes a finding and reads a running node, with how many findings it makes and the line the
# genesis stage prints for not running it. A finding added to one of these is a finding the genesis stage does not
# give: it is counted here once someone has seen that it needs the running node.
NEEDS_A_RUNNING_NODE = {
    "check_public_rpc": (3, "[3 rpc] what each public RPC URL serves, probed live"),
    "check_node_genesis": (3, "[8 node] the genesis and chain each authority's running node serves, the binary and "
                              "chain spec file it runs, and when its --chain path last changed"),
    "check_served_chain": (1, "[8 node] the genesis and chain each authority's running node serves, the binary and "
                              "chain spec file it runs, and when its --chain path last changed"),
    "check_chain_spec_age": (1, "[8 node] the genesis and chain each authority's running node serves, the binary and "
                                "chain spec file it runs, and when its --chain path last changed"),
    "check_environment": (5, "[8 node] the environment each authority's node process was started with: a mock "
                             "follower, or a setting other than its manifest declares"),
}


def test_every_finding_the_launch_gate_can_make_is_made_before_any_node_runs_or_named_as_not_run():
    """Read from the source, so that a rule added later is in the genesis stage or in this table: every function
    that makes a finding either reads a running node, and then the stage prints a line for it, or is reached from a
    step the stage runs."""
    functions = functions_of_the_preflight()
    makes = {name: findings_made(function) for name, function in functions.items() if findings_made(function)}
    reads_running = {name for name in makes if reaches({name}, functions) & READS_A_RUNNING_NODE}
    assert {name: makes[name] for name in reads_running} == {
        name: count for name, (count, _) in NEEDS_A_RUNNING_NODE.items()}
    assert {line for _, line in NEEDS_A_RUNNING_NODE.values()} <= set(lp.NOT_RUN[lp.RUNNING])
    steps = steps_of_a_run()
    gate = reaches(set().union(*(calls for _, calls in steps)), functions)
    stage = reaches(set().union(*(calls for needs, calls in steps if needs != lp.RUNNING)), functions)
    assert set(makes) - gate == set(), "a function makes a finding no step of the launch gate reaches"
    assert set(makes) - reads_running <= stage
    assert len(makes) > 40 and len(steps) > 30
    running_steps = set().union(*(calls for needs, calls in steps if needs == lp.RUNNING))
    assert reaches(running_steps, functions) & set(makes) - stage == set(NEEDS_A_RUNNING_NODE)


# ---------------------------------------------------------------------------
# The genesis stage reads each binary it is given once
# ---------------------------------------------------------------------------

def test_cli_the_genesis_stage_runs_the_bytes_it_hashed_of_a_binary_that_reads_another_way_each_time(clean, capsys):
    """A FIFO gives the pinned binary to its first reader and other bytes to every later one."""
    log = pinned_to_a_node(clean)
    fifo = clean.tmp_path / "node.fifo"
    os.mkfifo(fifo)
    pinned, done = clean.node_exe.read_bytes(), threading.Event()

    def feed() -> None:
        for payload in itertools.chain([pinned], itertools.repeat(b"#!/bin/sh\nexit 1\n")):
            if done.is_set():
                return
            with contextlib.suppress(BrokenPipeError), open(fifo, "wb") as writer:
                writer.write(payload)
            time.sleep(0.2)

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    try:
        code, out = genesis_stage(clean, capsys, binaries=[fifo])
    finally:
        done.set()
        os.close(os.open(fifo, os.O_RDONLY | os.O_NONBLOCK))
    assert (code, out.splitlines()[0]) == (0, GENESIS_PASS), out
    assert sorted(call["argv"][1] for call in node_calls(log)) == ["build-spec", "chain-id", "export-blocks",
                                                                   "export-blocks"]


def test_cli_the_genesis_stage_runs_the_bytes_it_hashed_of_a_binary_replaced_once_it_was_read(clean, capsys,
                                                                                              monkeypatch):
    log = pinned_to_a_node(clean)
    given = clean.tmp_path / "release-binary"
    given.write_bytes(clean.node_exe.read_bytes())
    read = lp.node_binaries

    def then_replaced(*args):
        staged = read(*args)
        given.write_text("#!/bin/sh\necho replaced\n")
        return staged

    monkeypatch.setattr(lp, "node_binaries", then_replaced)
    code, out = genesis_stage(clean, capsys, binaries=[given])
    assert (code, out.splitlines()[0]) == (0, GENESIS_PASS), out
    assert sorted(call["argv"][1] for call in node_calls(log)) == ["build-spec", "chain-id", "export-blocks",
                                                                   "export-blocks"]


def test_a_binary_that_is_not_the_pinned_one_when_the_genesis_stage_runs_it_is_a_reason(clean, tmp_path):
    """Whatever stands at the path the stage runs must hash to the pin, or the stage says it ran no binary for that
    authority."""
    spec = lp.load_spec(str(clean.spec_path()))
    other = tmp_path / "other"
    other.write_text("#!/bin/sh\nexit 1\n")
    launch = dict(clean.launch, nodes=[dict(node, exe=str(other)) if node["authority"] else node
                                       for node in clean.launch["nodes"]])
    lp.validate_launch(launch)
    pin = clean.launch["nodes"][0]["exe_sha256"]
    assert messages(lp.check_binary_genesis(spec, launch)) == [
        f"[8 node] authority val{i}: the node binary read for it has sha256 {sha256_pin(other)}, not its pinned "
        f"exe_sha256 {pin}: only the pinned binary is run to attest its genesis" for i in range(4)]


# ---------------------------------------------------------------------------
# A node whose name is no string, and a launch key file that cannot be written
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [["edge"], {"is": "edge"}, 7, None])
def test_a_node_name_that_is_no_string_is_an_input_error(name):
    launch = {"roles": {}, "supply": VALID_LOCK, "nodes": [{"name": name, "host": "edge", "authority": False}],
              "rpc_proxies": [{"name": "p", "node": "edge", "kind": "nginx", "config": "c"}]}
    with pytest.raises(lp.InputError) as refused:
        lp.validate_launch(launch)
    assert [str(error).split(":")[0] for error in refused.value.errors] == [
        "nodes[0] needs a name and a host", "rpc_proxies[0] runs on edge, which is not a declared node"]


def test_cli_a_node_name_that_is_no_string_is_an_input_error(clean, capsys):
    clean.launch["nodes"][-1]["name"] = ["edge"]
    signing_code, code, out = sign_and_check(clean.tmp_path, clean.prepare(), clean.launch, capsys, clean.kupo.url,
                                             clean.launch_key)
    assert (signing_code, code) == (2, 2)
    assert out.splitlines()[0] == "MAINNET LAUNCH PREFLIGHT: REFUSE (input) nodes[4] needs a name and a host"


def test_a_launch_key_whose_seed_cannot_be_written_leaves_no_file(tmp_path):
    """The file is created before the seed is written: a write the file system refuses must not leave an empty key
    file that a later run cannot replace."""
    out = tmp_path / "launch.key"

    def no_room() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

    done = subprocess.run([sys.executable, "-B", str(HERE / "launch_preflight.py"), "launch-key", "new", "--out",
                           str(out)], capture_output=True, text=True, preexec_fn=no_room)
    assert done.returncode == 2 and done.stdout == "", done.stderr
    assert done.stderr == (f"MAINNET LAUNCH PREFLIGHT: REFUSE (input) cannot write the launch key to {out}: File too "
                           "large\n")
    assert not out.exists()
    again = subprocess.run([sys.executable, "-B", str(HERE / "launch_preflight.py"), "launch-key", "new", "--out",
                            str(out)], capture_output=True, text=True)
    assert again.returncode == 0 and out.stat().st_mode & 0o777 == 0o600
