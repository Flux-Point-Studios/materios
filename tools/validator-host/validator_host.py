#!/usr/bin/env python3
"""A mainnet validator's own keys, the row and proof it hands out, and its systemd unit.

    validator_host.py keygen --keystore <dir> --node-key <file>
    validator_host.py show   --keystore <dir> --node-key <file>
    validator_host.py prove  --keystore <dir> --name <validator>
    validator_host.py verify <proof.json>
    validator_host.py unit   --launch <launch.json> --name <validator> --env-file <file> [--user <user>]

Run on the validator host, as the user the node runs as. No secret is printed by any command, and none leaves the
keystore directory and the node key file. Exit 0 when done, 1 with the reason after a refusal, 2 for a command line
that is none of the above. README.md gives the order."""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

import base58
import coincurve
import sr25519
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

# The node's key type of each session key, in the order a proof and the screen list them.
KEY_TYPES = {"aura": "aura", "grandpa": "gran", "cross_chain": "crch"}
POP_DOMAIN = "materios-validator-host-pop-v1"
CONNECTION_STRING = "DB_SYNC_POSTGRES_CONNECTION_STRING"
# A word systemd copies into the process unchanged between double quotes: no quote, escape, specifier or variable.
EXACT = re.compile(r"[ !#&-\[\]-~]*")
SEED = re.compile(r"0x[0-9a-f]{64}")


class Refused(Exception):
    pass


def public_key(key: str, seed: bytes) -> bytes:
    """The public key the node derives from a seed with no derivation path, by scheme."""
    if key == "aura":
        return sr25519.pair_from_seed(seed)[0]
    if key == "grandpa":
        return bytes(SigningKey(seed).verify_key)
    return coincurve.PrivateKey(seed).public_key.format(compressed=True)


def write_private(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(text)


def keygen(keystore: Path, node_key: Path) -> None:
    if keystore.exists() and any(keystore.iterdir()):
        raise Refused(f"{keystore} already holds entries: keygen never writes into a keystore in use")
    if node_key.exists():
        raise Refused(f"{node_key} already exists: keygen never writes over a node key")
    keystore.mkdir(mode=0o700, parents=True, exist_ok=True)
    node_key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for key, key_type in KEY_TYPES.items():
        seed = secrets.token_bytes(32)
        write_private(keystore / (key_type.encode().hex() + public_key(key, seed).hex()), json.dumps("0x" + seed.hex()))
    write_private(node_key, secrets.token_hex(32))


def read_seeds(keystore: Path) -> dict[str, bytes]:
    """Each session key's seed, from a keystore that holds exactly the three keys and names each by the public key
    its secret derives: the node signs with whatever a file holds, under the public key its name gives."""
    try:
        entries = sorted(keystore.iterdir())
    except OSError as e:
        raise Refused(f"{keystore} cannot be listed: {e.strerror}") from e
    types = {key_type.encode().hex(): key for key, key_type in KEY_TYPES.items()}
    found: dict[str, list[Path]] = {key: [] for key in KEY_TYPES}
    for entry in entries:
        if entry.name[:8] not in types:
            raise Refused(f"{entry} is no key entry of {', '.join(KEY_TYPES.values())}")
        found[types[entry.name[:8]]].append(entry)
    seeds = {}
    for key, paths in found.items():
        if len(paths) != 1:
            raise Refused(f"{keystore} holds {len(paths)} {KEY_TYPES[key]} entries: a validator holds exactly one")
        try:
            secret = json.loads(paths[0].read_text())
        except (OSError, ValueError) as e:
            raise Refused(f"{paths[0].name[:8]}… cannot be read as a keystore entry: {type(e).__name__}") from e
        if not isinstance(secret, str) or not SEED.fullmatch(secret):
            raise Refused(f"the {KEY_TYPES[key]} entry does not hold a 32-byte seed as 0x and lowercase hex: "
                          "it was not made by keygen")
        seeds[key] = bytes.fromhex(secret[2:])
        if paths[0].name[8:] != public_key(key, seeds[key]).hex():
            raise Refused(f"the {KEY_TYPES[key]} entry's secret does not derive the public key its name gives")
    return seeds


def peer_id(node_key: Path) -> str:
    try:
        text = node_key.read_text().strip()
    except OSError as e:
        raise Refused(f"{node_key} cannot be read: {e.strerror}") from e
    if not re.fullmatch("[0-9a-f]{64}", text):
        raise Refused(f"{node_key} does not hold a 32-byte ed25519 secret in hex")
    identity = bytes([0x08, 0x01, 0x12, 0x20]) + bytes(SigningKey(bytes.fromhex(text)).verify_key)
    return base58.b58encode(bytes([0x00, len(identity)]) + identity).decode()


def row(keys: dict[str, bytes]) -> str:
    return ":".join(keys[key].hex() for key in ("cross_chain", "aura", "grandpa"))


def show(keystore: Path, node_key: Path) -> str:
    keys = {key: public_key(key, seed) for key, seed in read_seeds(keystore).items()}
    return (f"aura key: 0x{keys['aura'].hex()}\n"
            f"grandpa key: 0x{keys['grandpa'].hex()}\n"
            f"partner-chain key: 0x{keys['cross_chain'].hex()}\n"
            f"peer id: {peer_id(node_key)}\n"
            f"candidates row: {row(keys)}\n")


def pop_message(name: str, keys: dict[str, bytes]) -> bytes:
    return f"{POP_DOMAIN}\n{name}\n{row(keys)}".encode()


def prove(keystore: Path, name: str) -> str:
    seeds = read_seeds(keystore)
    keys = {key: public_key(key, seed) for key, seed in seeds.items()}
    message = pop_message(name, keys)
    signatures = {
        "aura": sr25519.sign((keys["aura"], sr25519.pair_from_seed(seeds["aura"])[1]), message),
        "grandpa": SigningKey(seeds["grandpa"]).sign(message).signature,
        "cross_chain": coincurve.PrivateKey(seeds["cross_chain"]).sign(message),
    }
    return json.dumps({"name": name, **{key: "0x" + keys[key].hex() for key in KEY_TYPES},
                       "signatures": {key: "0x" + signatures[key].hex() for key in KEY_TYPES}}, indent=1) + "\n"


def signed(key: str, public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        if key == "aura":
            return sr25519.verify(signature, message, public)
        if key == "grandpa":
            VerifyKey(public).verify(message, signature)
            return True
        return coincurve.verify_signature(signature, message, public)
    except (BadSignatureError, ValueError, TypeError):
        return False


def verify(path: Path) -> str:
    try:
        doc = json.loads(path.read_text())
        name = doc["name"]
        keys = {key: bytes.fromhex(doc[key].removeprefix("0x")) for key in KEY_TYPES}
        signatures = {key: bytes.fromhex(doc["signatures"][key].removeprefix("0x")) for key in KEY_TYPES}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise Refused(f"{path} is not a proof this tool wrote: {type(e).__name__}") from e
    if not isinstance(name, str) or [len(keys[key]) for key in KEY_TYPES] != [32, 32, 33]:
        raise Refused(f"{path} is not a proof this tool wrote: a name, two 32-byte keys and a 33-byte key")
    message = pop_message(name, keys)
    for key in KEY_TYPES:
        if not signed(key, keys[key], signatures[key], message):
            raise Refused(f"the {key} signature does not verify for {name} and these three keys: "
                          "do not list this validator")
    return f"PASS: {name} signed with all three keys\ncandidates row: {row(keys)}\n"


def exact(word: str, what: str) -> str:
    if not isinstance(word, str) or not EXACT.fullmatch(word):
        raise Refused(f"{what} holds a character systemd would rewrite or cannot carry "
                      '(a quote, a backslash, %, $, a control or non-ASCII character)')
    return f'"{word}"'


def unit(launch: Path, name: str, env_file: str, user: str | None) -> str:
    try:
        nodes = json.loads(launch.read_text())["nodes"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Refused(f"{launch} is not a launch manifest: {type(e).__name__}") from e
    node = next((n for n in nodes if n.get("name") == name and n.get("authority") is True), None)
    if node is None:
        raise Refused(f"{launch} declares no authority named {name}")
    argv, env = node["argv"], node["env"]
    if not argv[0].startswith("/"):
        raise Refused(f"argv[0] of {name} must be the absolute path of the node binary: systemd runs nothing else, "
                      "and the launch gate compares it with the running process word for word")
    if not env_file.startswith("/") or not EXACT.fullmatch(env_file) or " " in env_file:
        raise Refused("--env-file must be an absolute path without spaces")
    for key in env:
        if not re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", key):
            raise Refused(f"{key!r} is no environment name")
    lines = ["[Unit]", f"Description=Materios mainnet validator {name}", "Wants=network-online.target",
             "After=network-online.target", "", "[Service]"]
    if user:
        lines.append(f"User={user}")
    lines.append("ExecStart=" + " ".join(exact(word, f"argument {i} of {name}") for i, word in enumerate(argv)))
    lines += ["Environment=" + exact(f"{key}={env[key]}", f"the setting {key}")
              for key in sorted(env) if key != CONNECTION_STRING]
    # RestartSec is the wait that keeps a restarted GRANDPA voter from voting twice in a round it already voted in.
    lines += [f"EnvironmentFile={env_file}", "Restart=on-failure", "RestartSec=120", "LimitNOFILE=65536",
              "NoNewPrivileges=yes", "", "[Install]", f"WantedBy={'multi-user' if user else 'default'}.target"]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="validator_host.py")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("keygen", "show", "prove"):
        sub = commands.add_parser(command)
        sub.add_argument("--keystore", type=Path, required=True)
        if command == "prove":
            sub.add_argument("--name", required=True)
        else:
            sub.add_argument("--node-key", type=Path, required=True)
    commands.add_parser("verify").add_argument("proof", type=Path)
    sub = commands.add_parser("unit")
    sub.add_argument("--launch", type=Path, required=True)
    sub.add_argument("--name", required=True)
    sub.add_argument("--env-file", required=True)
    sub.add_argument("--user")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "keygen":
            keygen(args.keystore, args.node_key)
            out = show(args.keystore, args.node_key)
        elif args.command == "show":
            out = show(args.keystore, args.node_key)
        elif args.command == "prove":
            out = prove(args.keystore, args.name)
        elif args.command == "verify":
            out = verify(args.proof)
        else:
            out = unit(args.launch, args.name, args.env_file, args.user)
    except Refused as e:
        print(f"validator-host: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
