#!/usr/bin/env python3
"""A mainnet validator's own keys, the row and proof it hands out, and its systemd unit.

    validator_host.py keygen --keystore <dir> --node-key <file>
    validator_host.py show   --keystore <dir> --node-key <file>
    validator_host.py prove  --keystore <dir> --name <validator>
    validator_host.py verify <proof.json> --launch <launch.json> --name <validator>
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
from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "launch-preflight"))
import launch_preflight as lp  # noqa: E402

# The node's key type of each session key, in the order a proof and the screen list them.
KEY_TYPES = {"aura": "aura", "grandpa": "gran", "cross_chain": "crch"}
POP_DOMAIN = "materios-validator-host-pop-v1"
CONNECTION_STRING = "DB_SYNC_POSTGRES_CONNECTION_STRING"
# A word systemd copies into the process unchanged between double quotes: no quote, escape, specifier or variable.
EXACT = re.compile(r"[ !#&-\[\]-~]*")
SEED = re.compile(r"0x[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
# Options whose value is a secret: a unit is world-readable and the manifest is signed and handed round.
SECRET_OPTIONS = ("--password", "--node-key")
# What json.loads raises on a file that is no JSON, or nested past what Python parses.
NOT_JSON = (ValueError, RecursionError)


class Refused(Exception):
    pass


def unusable(key: str, public: bytes) -> str | None:
    """Why no secret stands behind these bytes as a key of their scheme, or None. The ristretto identity and an
    ed25519 key of small order verify a signature anyone can write; the rest decode to no key at all."""
    if key == "aura":
        if public == bytes(32):
            return "the all-zero key, whose sr25519 signature of any message needs no secret"
        try:
            sr25519.derive_pubkey((bytes(32), public), b"")
        except ValueError:
            return "no sr25519 key: the bytes are no canonical ristretto point"
    elif key == "grandpa":
        if not crypto_core_ed25519_is_valid_point(public):
            return ("no ed25519 key a secret makes: a point of small order, whose signature of any message needs "
                    "no secret, or bytes that are no canonical point of the prime-order group")
    elif not lp.secp256k1_point(public):
        return "no ECDSA key: not 0x02 or 0x03 and the x of a point on secp256k1"
    return None


def public_key(key: str, seed: bytes) -> bytes:
    """The public key the node derives from a seed with no derivation path, by scheme."""
    if key == "aura":
        return sr25519.pair_from_seed(seed)[0]
    if key == "grandpa":
        return bytes(SigningKey(seed).verify_key)
    return coincurve.PrivateKey(seed).public_key.format(compressed=True)


def private_directory(path: Path) -> None:
    """Make the directory and each missing one above it, every one 0700 whatever the umask."""
    for missing in reversed([d for d in (path, *path.parents) if not d.exists()]):
        missing.mkdir()
        missing.chmod(0o700)


def keygen(keystore: Path, node_key: Path) -> None:
    if keystore.exists() and any(keystore.iterdir()):
        raise Refused(f"{keystore} already holds entries: keygen never writes into a keystore in use")
    if keystore.resolve() in node_key.resolve().parents:
        raise Refused(f"{node_key} is inside the keystore, where the node reads every file as a session key")
    files = {node_key: secrets.token_bytes(32).hex()}
    for key, key_type in KEY_TYPES.items():
        seed = secrets.token_bytes(32)
        files[keystore / (key_type.encode().hex() + public_key(key, seed).hex())] = json.dumps("0x" + seed.hex())
    written = []
    try:
        private_directory(node_key.parent)
        for path, text in files.items():
            # O_EXCL neither opens an existing file nor follows a link at the path.
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
                written.append(path)
                out.write(text)
            if path == node_key:
                private_directory(keystore)
                keystore.chmod(0o700)
    except OSError as e:
        for path in written:
            path.unlink()
        if isinstance(e, FileExistsError) and not written:
            raise Refused(f"{node_key} already exists: keygen never writes over a node key") from e
        raise Refused(f"{e.filename}: {e.strerror}; nothing was written") from e


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
        except (OSError, *NOT_JSON) as e:
            raise Refused(f"{paths[0].name[:8]}… cannot be read as a keystore entry: {type(e).__name__}") from e
        if not isinstance(secret, str) or not SEED.fullmatch(secret):
            raise Refused(f"the {KEY_TYPES[key]} entry does not hold a 32-byte seed as 0x and lowercase hex: "
                          "it was not made by keygen")
        seeds[key] = bytes.fromhex(secret[2:])
        try:
            public = public_key(key, seeds[key])
        except ValueError as e:
            raise Refused(f"the {KEY_TYPES[key]} entry holds no secret key of its scheme") from e
        if paths[0].name[8:] != public.hex():
            raise Refused(f"the {KEY_TYPES[key]} entry's secret does not derive the public key its name gives")
        if reason := unusable(key, public):
            raise Refused(f"the {KEY_TYPES[key]} entry's public key is {reason}")
    return seeds


def peer_id(node_key: Path) -> str:
    try:
        text = node_key.read_bytes().decode("ascii", "replace").strip()
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


def authority(launch: Path, name: str) -> dict:
    try:
        nodes = json.loads(launch.read_text())["nodes"]
        found = [n for n in nodes if n.get("name") == name and n.get("authority") is True]
    except (OSError, *NOT_JSON, KeyError, TypeError, AttributeError) as e:
        raise Refused(f"{launch} is not a launch manifest: {type(e).__name__}") from e
    if len(found) != 1:
        raise Refused(f"{launch} declares no authority named {name}" if not found else
                      f"{launch} declares {len(found)} authorities named {name}")
    return found[0]


def declared_keys(node: dict, name: str) -> dict[str, bytes]:
    """The three keys a manifest entry declares, each as the launch preflight reads it: 0x and lowercase hex, or
    for a 32-byte key an SS58 address."""
    keys = {}
    for key, size in (("aura", 32), ("grandpa", 32), ("cross_chain", 33)):
        try:
            keys[key] = lp.decode_public_key(node.get(key))
        except (ValueError, lp.InputError, TypeError, AttributeError) as e:
            raise Refused(f"the manifest's {key} key of {name} is no {size}-byte public key") from e
        if len(keys[key]) != size:
            raise Refused(f"the manifest's {key} key of {name} is no {size}-byte public key")
        if reason := unusable(key, keys[key]):
            raise Refused(f"the manifest's {key} key of {name} is {reason}: do not list this validator")
    return keys


def verify(path: Path, launch: Path, name: str) -> str:
    """PASS means the three keys the manifest declares for this validator each signed this name and their row. The
    proof brings the signatures alone: nothing of it is printed, and its own name and keys only have to agree."""
    keys = declared_keys(authority(launch, name), name)
    try:
        doc = json.loads(path.read_text())
        claimed = {key: doc[key] for key in ("name", *KEY_TYPES)}
        signatures = {key: bytes.fromhex(doc["signatures"][key].removeprefix("0x")) for key in KEY_TYPES}
    except (OSError, *NOT_JSON, KeyError, TypeError, AttributeError) as e:
        raise Refused(f"{path} is not a proof this tool wrote: {type(e).__name__}") from e
    if claimed["name"] != name:
        raise Refused(f"{path} names another validator than {name}: do not list it under this name")
    for key in KEY_TYPES:
        if claimed[key] != "0x" + keys[key].hex():
            raise Refused(f"{path} is for other keys than the manifest's {name}: its {key} key is not the one "
                          "the manifest declares")
    message = pop_message(name, keys)
    for key in KEY_TYPES:
        if not signed(key, keys[key], signatures[key], message):
            raise Refused(f"the {key} signature does not verify for {name} and the manifest's three keys: "
                          "do not list this validator")
    return f"PASS: {name} holds the three keys the manifest declares for it\ncandidates row: {row(keys)}\n"


def exact(word: str, what: str) -> str:
    if not isinstance(word, str) or not EXACT.fullmatch(word):
        raise Refused(f"{what} holds a character systemd would rewrite or cannot carry "
                      '(a quote, a backslash, %, $, a control or non-ASCII character)')
    return f'"{word}"'


def unit(launch: Path, name: str, env_file: str, user: str | None) -> str:
    node = authority(launch, name)
    argv, env = node.get("argv"), node.get("env")
    if not isinstance(argv, list) or not argv or not all(isinstance(word, str) for word in argv):
        raise Refused(f"the argv of {name} is not a list of one or more words")
    if not isinstance(env, dict) or not all(isinstance(value, str) for value in env.values()):
        raise Refused(f"the env of {name} is not a table of settings, each a string")
    if user is not None and not USER.fullmatch(user):
        raise Refused("--user is no user name: a lowercase letter or _, then lowercase letters, digits, _ or -")
    if not argv[0].startswith("/"):
        raise Refused(f"argv[0] of {name} must be the absolute path of the node binary: systemd runs nothing else, "
                      "and the launch gate compares it with the running process word for word")
    flags = [word.partition("=")[0] for word in argv]
    if "--validator" not in flags:
        raise Refused(f"the argv of {name} is without --validator: an authority that is no validator authors nothing")
    if dev := sorted(lp.DEV_KEYRING_FLAGS.intersection(flags)):
        raise Refused(f"a validator must not run with {dev[0]}, which loads keys every developer holds")
    if secret := [flag for flag in SECRET_OPTIONS if flag in flags]:
        raise Refused(f"{secret[0]} puts a secret in its argv, which the unit and the signed manifest show to "
                      f"everyone: give {secret[0]}-file or --password-filename")
    chain = lp._flag(argv, "--chain")
    if flags.count("--chain") != 1 or not chain or not chain.startswith("/"):
        raise Refused(f"the argv of {name} must give --chain once, as the absolute path of the spec file: a name "
                      "(dev, local, preprod) starts a chain built into the node, and the unit has no working directory "
                      "for a relative path")
    try:
        listeners = lp.rpc_listeners(name, argv)
    except lp.InputError as e:
        raise Refused(str(e)) from e
    for port, external, methods in listeners:
        if external:
            raise Refused(f"the RPC listener on port {port} of {name} listens beyond loopback: a validator's RPC "
                          "stays on loopback")
        if methods != "safe":
            raise Refused(f"the RPC listener on port {port} of {name} serves methods other than safe: give "
                          "--rpc-methods safe, and methods=safe in every --experimental-rpc-endpoint")
    if not env_file.startswith("/") or not EXACT.fullmatch(env_file) or " " in env_file:
        raise Refused("--env-file must be an absolute path without spaces")
    for key in env:
        if not re.fullmatch("[A-Za-z_][A-Za-z0-9_]*", key):
            raise Refused(f"{key!r} is no environment name")
        if key.upper().startswith("LD_"):
            raise Refused(f"{key} is a setting of the dynamic loader, which runs other code in the node")
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
    for command in ("verify", "unit"):
        sub = commands.add_parser(command)
        sub.add_argument("--launch", type=Path, required=True)
        sub.add_argument("--name", required=True)
        if command == "verify":
            sub.add_argument("proof", type=Path)
        else:
            sub.add_argument("--env-file", required=True)
            sub.add_argument("--user")
    args = parser.parse_args(argv)
    try:
        if "name" in args and not NAME.fullmatch(args.name):
            raise Refused("--name is no validator name: 1 to 64 of the letters A-Z and a-z, digits, '.', '_' and '-'")
        if args.command == "keygen":
            keygen(args.keystore, args.node_key)
            out = show(args.keystore, args.node_key)
        elif args.command == "show":
            out = show(args.keystore, args.node_key)
        elif args.command == "prove":
            out = prove(args.keystore, args.name)
        elif args.command == "verify":
            out = verify(args.proof, args.launch, args.name)
        else:
            out = unit(args.launch, args.name, args.env_file, args.user)
    except Refused as e:
        print(f"validator-host: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"validator-host: {e.filename}: {e.strerror}", file=sys.stderr)
        return 1
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
