#!/usr/bin/env python3
"""Which session keys a running Materios validator holds, read from its keystore.

`author_hasKey` is an unsafe RPC method, so a validator on `--rpc-methods safe`
refuses it. At polkadot-stable2409-4 it answers from the key file alone:
`LocalKeystore::has_keys` opens `<keystore>/<hex key type><hex public>` and
parses it as a JSON string (sc-keystore local.rs:166, 512, 556). This probe finds
that directory the way the node does and checks that the node's user can open
each file. It never opens one: a key file holds the secret.

It runs on the validator host with the standard library only:

    ssh HOST python3 - --chain-suffix chain-spec-v6-raw.json aura gran < seat_keys.py
"""
import argparse
import json
import os
import sys
from pathlib import Path

HEX = frozenset("0123456789abcdef")


class SeatKeyError(Exception):
    """The keystore the node reads cannot be determined, so the probe gives no answer."""


def key_type_hex(key_type: str) -> str:
    if not (key_type.isascii() and len(key_type) == 4):
        raise SeatKeyError(f"key type {key_type!r} is not 4 ASCII bytes")
    return key_type.encode().hex()


def option(argv: list[str], long: str, short: str | None = None) -> str | None:
    values = []
    for i, a in enumerate(argv):
        if a == long or a == short:
            values.append(argv[i + 1] if i + 1 < len(argv) else None)
        elif a.startswith(long + "="):
            values.append(a[len(long) + 1:])
        elif short and a.startswith(short) and not a.startswith("--"):
            values.append(a[len(short):].removeprefix("="))
    if len(values) > 1:
        raise SeatKeyError(f"{long} is given more than once")
    if values and values[0] is None:
        raise SeatKeyError(f"{long} has no value")
    return values[0] if values else None


def on_host(proc_dir: Path, path: str) -> Path:
    # Paths are the node's own: absolute ones live under its root (a container's
    # filesystem), relative ones under its working directory.
    p = Path(path)
    return proc_dir / "root" / p.relative_to("/") if p.is_absolute() else proc_dir / "cwd" / p


def find_validator(proc: Path, chain_suffix: str) -> tuple[int, list[str]]:
    found = []
    for d in proc.iterdir():
        if not d.name.isdigit():
            continue
        try:
            argv = [a.decode(errors="surrogateescape") for a in (d / "cmdline").read_bytes().split(b"\0") if a]
        except OSError:
            continue
        if (argv and os.path.basename(argv[0]).startswith("materios-node") and "--validator" in argv
                and (option(argv, "--chain") or "").endswith(chain_suffix)):
            found.append((int(d.name), argv))
    if len(found) != 1:
        raise SeatKeyError(f"{len(found)} validator processes run a chain spec ending in {chain_suffix}; "
                           "expected exactly 1")
    return found[0]


def effective_uid(proc_dir: Path) -> int:
    for line in (proc_dir / "status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[2])
    raise SeatKeyError(f"{proc_dir}/status has no Uid line")


def keystore_dir(proc_dir: Path, argv: list[str]) -> str:
    """The keystore path as the node resolves it (sc-cli keystore_params.rs:78-81, run_cmd.rs:584-595)."""
    path = option(argv, "--keystore-path")
    if path is not None:
        return path
    if "--tmp" in argv:
        raise SeatKeyError("the node keeps its keystore in a temporary base path (--tmp)")
    base = option(argv, "--base-path", "-d")
    if base is None:
        if "--dev" in argv:
            raise SeatKeyError("the node keeps its keystore in a temporary base path (--dev)")
        raise SeatKeyError("the node runs with no --base-path, so it uses a platform default this probe does not guess")
    chain = option(argv, "--chain")
    if chain is None:
        raise SeatKeyError("the node runs with no --chain")
    try:
        spec = json.loads(on_host(proc_dir, chain).read_text())
    except (OSError, ValueError) as e:
        raise SeatKeyError(f"--chain {chain} is not a chain spec file the probe can read: {e}") from e
    spec_id = spec.get("id") if isinstance(spec, dict) else None
    if not isinstance(spec_id, str) or not spec_id:
        raise SeatKeyError(f"chain spec {chain} has no id")
    return os.path.join(base, "chains", spec_id, "keystore")


def keys_in(directory: Path, keystore: str, key_type: str) -> tuple[list[str], list[str]]:
    try:
        names = os.listdir(directory)
    except OSError as e:
        raise SeatKeyError(f"no keystore at {keystore}: {e.strerror}") from e
    prefix = key_type_hex(key_type)
    held, unreadable = [], []
    for name in names:
        public = name[len(prefix):]
        if not (name.startswith(prefix) and public and len(public) % 2 == 0 and set(public) <= HEX):
            continue
        path = directory / name
        (held if os.path.isfile(path) and os.access(path, os.R_OK) else unreadable).append("0x" + public)
    return sorted(held), sorted(unreadable)


def probe(proc: Path, chain_suffix: str, key_types: list[str]) -> dict:
    for t in key_types:
        key_type_hex(t)
    pid, argv = find_validator(Path(proc), chain_suffix)
    proc_dir = Path(proc) / str(pid)
    uid = effective_uid(proc_dir)
    if uid != os.geteuid():
        raise SeatKeyError(f"the node runs as uid {uid}; run the probe as that user, "
                           "so file access is judged as the node judges it")
    keystore = keystore_dir(proc_dir, argv)
    directory = on_host(proc_dir, keystore)
    found = {t: keys_in(directory, keystore, t) for t in key_types}
    return {"pid": pid, "keystore": keystore,
            "held": {t: h for t, (h, _) in found.items()},
            "unreadable": {t: u for t, (_, u) in found.items()}}


def main() -> int:
    ap = argparse.ArgumentParser(description="List the session keys a running validator's keystore holds.")
    ap.add_argument("--proc", type=Path, default=Path("/proc"))
    ap.add_argument("--chain-suffix", required=True,
                    help="end of the validator's --chain path, e.g. chain-spec-v6-raw.json")
    ap.add_argument("key_types", nargs="+", help="4-byte key types, e.g. aura gran")
    a = ap.parse_args()
    try:
        out = probe(a.proc, a.chain_suffix, a.key_types)
    except SeatKeyError as e:
        print(f"seat-keys: {e}", file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
