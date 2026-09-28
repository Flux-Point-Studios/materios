#!/usr/bin/env python3
"""Regenerate well_known_keys.json: the public half of every key whose secret
is public knowledge.

    python3 gen_well_known_keys.py <polkadot-sdk checkout> <dir of public repo clones> > well_known_keys.json

The Substrate development keys are derived from sp-core's DEV_PHRASE, which is
read from a polkadot-sdk checkout rather than copied here. Each name in
sp-keyring (//Alice .. //Ferdie, their //stash accounts, //One, //Two) and the
bare phrase are derived under sr25519, ed25519 and ecdsa, with Substrate's hard
derivation (the "<Scheme>HDKD" blake2 junction for ed25519 and ecdsa).

Every commit of each repo in PUBLIC_REPOS (cloned under the second argument) is
swept for secrets committed as string literals: a BIP39 phrase with a valid
checksum, a 0x-hex 32-byte seed under a name that marks it secret, and a bare
`//Path` URI, which derives from the dev phrase. Each is derived under all three
schemes; only the public keys are written.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import ecdsa
import nacl.signing
import sr25519
from bip39 import bip39_to_mini_secret
from mnemonic import Mnemonic
from substrateinterface import Keypair, KeypairType

from launch_preflight import blake2_256, compact

NAMES = ["Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie"]
UNSTASHED = ["One", "Two"]

# The public repos that hold Substrate key code or configuration.
PUBLIC_REPOS = ["materios", "materios-gateway", "materios-intent-settlement", "materios-operator-kit",
                "orynq-sdk", "orynq-observe-seed", "docs", "substrate-suri-ffi", "partner-chains"]

# Keys whose secret was published outside a repository. An exposure that is not
# yet public knowledge goes in an operator table passed to the preflight with
# --extra-well-known instead.
COMPROMISED = [
    ("retired validator key, mnemonic published on-chain", "sr25519",
     "7e27bb13fd6fb62cc0e7c59916952c8c214960904208295a0d70c4c48e2a9a29"),
    ("retired validator key, mnemonic published on-chain", "ed25519",
     "6c484a9d5a8d0182e0f3bf9d8ffc4ca7070fd08da47329afca79f4b3df6aaa7e"),
]

STRING = re.compile(r"""(["'`])([^"'`\\\n]{1,400})\1""")
HARD_PATH = r"(?://[\w-]+)*"
PHRASE_URI = re.compile(rf"\s*([a-z]+(?: +[a-z]+){{11,23}})\s*({HARD_PATH})\s*")
SEED = re.compile(rf"0x([0-9a-fA-F]{{64}})({HARD_PATH})")
DEV_URI = re.compile(r"(?://[\w-]+)+")
SECRET_NAME = re.compile(r"seed|secret|suri|private|mini|skey|signing", re.I)
CHECKSUM = Mnemonic("english")
# What Rust's u64::from_str accepts.
U64 = re.compile(r"\+?[0-9]+")


def scale_str(s: str) -> bytes:
    raw = s.encode()
    return compact(len(raw)) + raw


def chain_code(junction: str) -> bytes:
    """sp-core's DeriveJunction: a junction that parses as a u64 is its
    little-endian bytes, any other its SCALE string, hashed past 32 bytes."""
    if U64.fullmatch(junction) and int(junction) < 1 << 64:
        encoded = int(junction).to_bytes(8, "little")
    else:
        encoded = scale_str(junction)
    return encoded.ljust(32, b"\0") if len(encoded) <= 32 else blake2_256(encoded)


def hard_derive(seed: bytes, junctions: list[str], hdkd: str) -> bytes:
    for junction in junctions:
        seed = blake2_256(scale_str(hdkd) + seed + chain_code(junction))
    return seed


def dev_phrase(sdk: Path) -> str:
    src = (sdk / "substrate/primitives/core/src/crypto.rs").read_text()
    return re.search(r'pub const DEV_PHRASE: &str =\s*"([^"]+)"', src).group(1)


def derive(label: str, secret: str, path: str):
    """sr25519, ed25519 and ecdsa keys for a phrase or 0x-hex seed and a hard path."""
    junctions = [j for j in path.split("//") if j]
    root = bytes.fromhex(secret[2:]) if secret.startswith("0x") else bytes(bip39_to_mini_secret(secret, ""))
    pair = Keypair.create_from_seed(root.hex(), crypto_type=KeypairType.SR25519)
    sr, secret_key = pair.public_key, pair.private_key
    for junction in junctions:
        _, sr, secret_key = sr25519.hard_derive_keypair((chain_code(junction), sr, secret_key), b"")
    yield {"label": label, "scheme": "sr25519", "public": sr.hex(), "account": sr.hex()}
    ed = nacl.signing.SigningKey(hard_derive(root, junctions, "Ed25519HDKD")).verify_key.encode()
    yield {"label": label, "scheme": "ed25519", "public": ed.hex(), "account": ed.hex()}
    ec = ecdsa.SigningKey.from_string(hard_derive(root, junctions, "Secp256k1HDKD"), curve=ecdsa.SECP256k1)
    compressed = ec.get_verifying_key().to_string("compressed")
    yield {"label": label, "scheme": "ecdsa", "public": compressed.hex(), "account": blake2_256(compressed).hex()}


def dev_entries(phrase: str):
    paths = [[]] + [[n] for n in NAMES] + [[n, "stash"] for n in NAMES] + [[n] for n in UNSTASHED]
    for junctions in paths:
        path = "".join("//" + j for j in junctions)
        yield from derive(path or "dev phrase root", phrase, path)


def committed_blobs(repo: Path):
    """Every text blob reachable from any ref of `repo`."""
    listing = subprocess.run(["git", "-C", repo, "rev-list", "--objects", "--all", "--missing=allow-promisor"],
                             capture_output=True, text=True, check=True).stdout
    blobs = {}
    for line in listing.splitlines():
        sha, _, name = line.partition(" ")
        if name:
            blobs.setdefault(sha, name)
    present = subprocess.run(["git", "-C", repo, "cat-file", "--batch-check=%(objectname) %(objecttype)",
                              "--batch-all-objects"], capture_output=True, text=True, check=True).stdout
    shas = sorted(sha for sha, kind in (line.split() for line in present.splitlines())
                  if kind == "blob" and sha in blobs)
    cat = subprocess.run(["git", "-C", repo, "cat-file", "--batch"], input=("\n".join(shas) + "\n").encode(),
                         capture_output=True, check=True).stdout
    pos = 0
    while pos < len(cat):
        header_end = cat.index(b"\n", pos)
        size = int(cat[pos:header_end].split()[2])
        body = cat[header_end + 1:header_end + 1 + size]
        pos = header_end + 2 + size
        try:
            yield body.decode()
        except UnicodeDecodeError:
            continue


def committed_secrets(text: str):
    """(secret, path) pairs and bare dev-phrase paths in string literals."""
    for literal in STRING.finditer(text):
        body = literal.group(2)
        phrase = PHRASE_URI.fullmatch(body)
        if phrase and CHECKSUM.check(phrase.group(1)):
            yield " ".join(phrase.group(1).split()), phrase.group(2)
        seed = SEED.fullmatch(body)
        if seed and SECRET_NAME.search(text[max(0, literal.start() - 60):literal.start()]):
            yield "0x" + seed.group(1).lower(), seed.group(2)
        if DEV_URI.fullmatch(body):
            yield None, body


def swept_entries(clones: Path, phrase: str):
    found = {}
    for repo in PUBLIC_REPOS:
        path = clones / repo
        if not (path / ".git").exists():
            sys.exit(f"missing clone of {repo} under {clones}")
        for text in committed_blobs(path):
            for secret, derivation in committed_secrets(text):
                if secret in (None, phrase):
                    found.setdefault((phrase, derivation), derivation or "dev phrase root")
                else:
                    found.setdefault((secret, derivation), f"{repo} test key, secret committed to a public repo")
    for (secret, derivation), label in sorted(found.items(), key=lambda item: (item[1], item[0][1])):
        yield from derive(label, secret, derivation)


def main():
    phrase = dev_phrase(Path(sys.argv[1]))
    seen, keys = set(), []
    compromised = ({"label": label, "scheme": scheme, "public": pub,
                    "account": blake2_256(bytes.fromhex(pub)).hex() if scheme == "ecdsa" else pub}
                   for label, scheme, pub in COMPROMISED)
    for entry in [*dev_entries(phrase), *swept_entries(Path(sys.argv[2]), phrase), *compromised]:
        if (entry["scheme"], entry["public"]) not in seen:
            seen.add((entry["scheme"], entry["public"]))
            keys.append(entry)
    table = {"dev_phrase_blake2_256": blake2_256(" ".join(phrase.split()).encode()).hex(), "keys": keys}
    json.dump(table, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
