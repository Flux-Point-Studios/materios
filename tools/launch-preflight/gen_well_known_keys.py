#!/usr/bin/env python3
"""Regenerate well_known_keys.json: the public half of every key whose secret
is public knowledge.

The Substrate development keys are derived from sp-core's DEV_PHRASE, which is
read from a polkadot-sdk checkout rather than copied here. Each name in
sp-keyring (//Alice .. //Ferdie, their //stash accounts, //One, //Two) and the
bare phrase are derived under sr25519, ed25519 and ecdsa, with Substrate's hard
derivation (the "<Scheme>HDKD" blake2 junction for ed25519 and ecdsa).

    python3 gen_well_known_keys.py <polkadot-sdk checkout> > well_known_keys.json
"""
import hashlib
import json
import re
import sys
from pathlib import Path

import ecdsa
import nacl.signing
from bip39 import bip39_to_mini_secret
from substrateinterface import Keypair, KeypairType

NAMES = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"]
UNSTASHED = ["One", "Two"]

# Keys whose secret is public: retired keys whose secret was published, and keys
# whose seed a public repo commits as a test fixture. Only the public keys belong
# here; an exposure that is not yet public knowledge goes in an operator table
# passed to the preflight with --extra-well-known.
ORYNQ_OBSERVER = "orynq-sdk e2e test observer, seed committed to a public repo"
COMPROMISED = [
    ("retired validator key, mnemonic published on-chain", "sr25519",
     "7e27bb13fd6fb62cc0e7c59916952c8c214960904208295a0d70c4c48e2a9a29"),
    ("retired validator key, mnemonic published on-chain", "ed25519",
     "6c484a9d5a8d0182e0f3bf9d8ffc4ca7070fd08da47329afca79f4b3df6aaa7e"),
    (ORYNQ_OBSERVER, "sr25519", "1a4fee48c1ba1a48e8cd43782a8485d635aa91cfb82cbb477f0c1c576bc4031c"),
    (ORYNQ_OBSERVER, "ed25519", "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"),
    (ORYNQ_OBSERVER, "ecdsa", "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"),
]


def blake2_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def scale_str(s: str) -> bytes:
    raw = s.encode()
    assert len(raw) < 64
    return bytes([len(raw) << 2]) + raw


def chain_code(junction: str) -> bytes:
    encoded = scale_str(junction)
    return encoded.ljust(32, b"\0") if len(encoded) <= 32 else blake2_256(encoded)


def hard_derive(seed: bytes, junctions: list[str], hdkd: str) -> bytes:
    for junction in junctions:
        seed = blake2_256(scale_str(hdkd) + seed + chain_code(junction))
    return seed


def dev_phrase(sdk: Path) -> str:
    src = (sdk / "substrate/primitives/core/src/crypto.rs").read_text()
    return re.search(r'pub const DEV_PHRASE: &str =\s*"([^"]+)"', src).group(1)


def entries(phrase: str):
    root = bytes(bip39_to_mini_secret(phrase, ""))
    paths = [[]] + [[n] for n in NAMES] + [[n, "stash"] for n in NAMES] + [[n] for n in UNSTASHED]
    for junctions in paths:
        label = "".join("//" + j for j in junctions) or "dev phrase root"
        uri = phrase + "".join("//" + j for j in junctions)
        sr = Keypair.create_from_uri(uri, crypto_type=KeypairType.SR25519).public_key
        yield {"label": label, "scheme": "sr25519", "public": sr.hex(), "account": sr.hex()}
        ed = nacl.signing.SigningKey(hard_derive(root, junctions, "Ed25519HDKD")).verify_key.encode()
        yield {"label": label, "scheme": "ed25519", "public": ed.hex(), "account": ed.hex()}
        secret = hard_derive(root, junctions, "Secp256k1HDKD")
        ec = ecdsa.SigningKey.from_string(secret, curve=ecdsa.SECP256k1).get_verifying_key()
        compressed = ec.to_string("compressed")
        yield {"label": label, "scheme": "ecdsa", "public": compressed.hex(),
               "account": blake2_256(compressed).hex()}


def main():
    phrase = dev_phrase(Path(sys.argv[1]))
    table = {
        "dev_phrase_blake2_256": blake2_256(" ".join(phrase.split()).encode()).hex(),
        "keys": list(entries(phrase)) + [
            {"label": label, "scheme": scheme, "public": pub,
             "account": blake2_256(bytes.fromhex(pub)).hex() if scheme == "ecdsa" else pub}
            for label, scheme, pub in COMPROMISED
        ],
    }
    json.dump(table, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
