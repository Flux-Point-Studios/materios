#!/usr/bin/env python3
"""Which session keys a running Materios validator's keystore names: an upper bound on the keys it holds.

`author_hasKey` is an unsafe RPC method, so a validator on `--rpc-methods safe`
refuses it. At polkadot-stable2409-4, `LocalKeystore::has_keys` answers from an
in-memory map of dev keys first, then from the file
`<keystore>/<hex key type><hex public>`, parsed as a JSON string (sc-keystore
local.rs:166, 512-526, 556). This probe refuses a node that keeps dev keys in
memory, finds the keystore directory the node reads, and lists the key files in
it. It never opens one: a key file holds the secret. A key it names on one host
and no other proves no other host signs with it, never that this one does.

It runs on the validator host, as the node's user or root, with the standard
library only:

    ssh HOST python3 - --chain-id materios_preprod_v6 aura gran < seat_keys.py
"""
import argparse
import json
import os
import stat
import sys
from pathlib import Path

if sys.version_info < (3, 10):
    print("seat-keys: needs Python 3.10 or newer", file=sys.stderr)
    sys.exit(2)

HEX = frozenset("0123456789abcdef")
# Each makes the node an authority (sc-cli run_cmd.rs:413-416) and keeps a dev
# seed's keys in its keystore's in-memory map (run_cmd.rs:386-393).
KEYRING_FLAGS = frozenset({"--alice", "--bob", "--charlie", "--dave", "--eve", "--ferdie", "--one", "--two", "--dev"})
AUTHORITY_FLAGS = KEYRING_FLAGS | {"--validator"}
# The node's database sits at <base path>/chains/<chain spec id>/db or paritydb (sc-cli config.rs:230-231, 486).
DATABASE_DIRS = ("db", "paritydb")


class SeatKeyError(Exception):
    """The probe cannot tell which keys the node holds, so it gives no answer."""


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
        elif short and a.startswith(short):
            values.append(a[len(short):].removeprefix("="))
    if len(values) > 1:
        raise SeatKeyError(f"{long} is given more than once")
    if values and values[0] is None:
        raise SeatKeyError(f"{long} has no value")
    return values[0] if values else None


def authorities(proc: Path) -> list[tuple[int, list[str]]]:
    """Every process with an authority flag of its own. A process that exits while the probe reads it is skipped."""
    try:
        pids = sorted(int(d.name) for d in proc.iterdir() if d.name.isdigit())
    except OSError as e:
        raise SeatKeyError(f"cannot list the processes in {proc}: {e.strerror}; the probe reads Linux's /proc") from e
    found = []
    for pid in pids:
        try:
            raw = (proc / str(pid) / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as e:
            raise SeatKeyError(f"cannot read the argv of process {pid}: {e.strerror}") from e
        argv = [a.decode(errors="surrogateescape") for a in raw.split(b"\0") if a]
        if AUTHORITY_FLAGS.intersection(argv):
            found.append((pid, argv))
    return found


def running_chain_id(proc_dir: Path, argv: list[str]) -> str:
    """The id of the chain spec the process runs: the one whose database it holds open under its --base-path, at
    <base path>/chains/<id>/db or paritydb. The node reads its spec once, at its start, so the file its --chain names
    may hold another spec by now, and a spec built into the node has no file. The kernel names an open file by its
    resolved path, so a database reached through a link lands outside the base path, and refuses."""
    name = f"process {proc_dir.name} ({os.path.basename(argv[0])})"
    base = option(argv, "--base-path", "-d")
    if base is None:
        raise SeatKeyError(f"{name} runs with an authority flag and no --base-path, so the probe cannot tell which "
                           "chain it runs")
    if not base.startswith("/") or ".." in base.split("/"):
        raise SeatKeyError(f"{name} runs with --base-path {base}; the probe matches its open database against an "
                           "absolute path without '..'")
    chains = os.path.join(os.path.normpath(base), "chains") + "/"
    fd_dir = proc_dir / "fd"
    links = []
    try:
        for fd in sorted(os.listdir(fd_dir), key=int):
            try:
                links.append(os.readlink(fd_dir / fd))
            except FileNotFoundError:
                continue
    except OSError as e:
        raise SeatKeyError(f"cannot read the open files of process {proc_dir.name}: {e.strerror}; run the probe as "
                           "the node's user or root") from e
    ids = set()
    for link in links:
        parts = link.split("/")
        if not any(parts[i] == "chains" and parts[i + 2] in DATABASE_DIRS for i in range(len(parts) - 2)):
            continue
        rest = link[len(chains):].split("/")
        if not link.startswith(chains) or len(rest) < 2 or rest[1] not in DATABASE_DIRS:
            raise SeatKeyError(f"{name} holds a chain database open at {link}, not at {chains}<id>/db or paritydb "
                               "under its --base-path")
        ids.add(rest[0])
    if len(ids) != 1:
        held = "no chain database" if not ids else f"{len(ids)} chains' databases"
        raise SeatKeyError(f"{name} runs with an authority flag and holds {held} open, so the probe cannot tell which "
                           "chain it runs")
    return ids.pop()


def keystore_path(argv: list[str], chain_id: str) -> str:
    """The keystore path as the node resolves it (sc-cli keystore_params.rs:78-81, run_cmd.rs:584-595)."""
    path = option(argv, "--keystore-path")
    if path is not None:
        return path
    if "--tmp" in argv:
        raise SeatKeyError("the node keeps its keystore in a temporary base path (--tmp)")
    return os.path.join(option(argv, "--base-path", "-d"), "chains", chain_id, "keystore")


def keystore_names(proc_dir: Path, keystore: str) -> list[str]:
    """The entries of the keystore directory, reached from the node's root for an absolute path and its working
    directory for a relative one. Every step must be a directory: the node follows a symbolic link from its own root,
    and the kernel would follow it from the probe's."""
    parts = [p for p in keystore.split("/") if p]
    if ".." in parts:
        raise SeatKeyError(f"the keystore path {keystore} climbs with '..'; the probe walks it one directory at a time")
    start = "root" if keystore.startswith("/") else "cwd"
    try:
        fd = os.open(proc_dir / start, os.O_RDONLY)
    except OSError as e:
        raise SeatKeyError(f"cannot open the {start} of process {proc_dir.name}: {e.strerror}; run the probe as the "
                           "node's user or root") from e
    try:
        for i, part in enumerate(parts):
            step = "/".join(parts[:i + 1])
            try:
                mode = os.stat(part, dir_fd=fd, follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode):
                    raise SeatKeyError(f"{step}, on the keystore path {keystore}, is a symbolic link")
                if not stat.S_ISDIR(mode):
                    raise SeatKeyError(f"{step}, on the keystore path {keystore}, is not a directory")
                step_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError as e:
                raise SeatKeyError(f"no keystore at {keystore}: {step} does not exist") from e
            except OSError as e:
                raise SeatKeyError(f"cannot open {step}, on the keystore path {keystore}: {e.strerror}") from e
            os.close(fd)
            fd = step_fd
        return os.listdir(fd)
    finally:
        os.close(fd)


def keys_of_type(names: list[str], key_type: str) -> list[str]:
    """Every entry named `<hex key type><lowercase hex public>`, whatever it is: the probe cannot judge what the node
    can open (its fsuid, groups, capabilities, ACLs, security modules), so it lists every key the node may load."""
    prefix = key_type_hex(key_type)
    publics = [name[len(prefix):] for name in names if name.startswith(prefix)]
    return sorted("0x" + p for p in publics if p and len(p) % 2 == 0 and set(p) <= HEX)


def probe(proc: Path, chain_id: str, key_types: list[str]) -> dict:
    for t in key_types:
        key_type_hex(t)
    proc = Path(proc)
    found = [(pid, argv) for pid, argv in authorities(proc) if running_chain_id(proc / str(pid), argv) == chain_id]
    if len(found) != 1:
        raise SeatKeyError(f"{len(found)} authority processes run chain {chain_id}; expected exactly 1")
    pid, argv = found[0]
    dev = sorted(KEYRING_FLAGS.intersection(argv))
    if dev:
        raise SeatKeyError(f"the node runs with {' '.join(dev)}, which keeps a dev seed's keys in memory, where no "
                           "file shows them")
    keystore = keystore_path(argv, chain_id)
    names = keystore_names(proc / str(pid), keystore)
    return {"pid": pid, "chain_id": chain_id, "keystore": keystore,
            "named": {t: keys_of_type(names, t) for t in key_types}}


def main() -> int:
    ap = argparse.ArgumentParser(description="List the session keys a running validator's keystore holds.")
    ap.add_argument("--proc", type=Path, default=Path("/proc"))
    ap.add_argument("--chain-id", required=True, help="the id of the chain spec the validator runs, e.g. "
                                                      "materios_preprod_v6")
    ap.add_argument("key_types", nargs="+", help="4-byte key types, e.g. aura gran")
    a = ap.parse_args()
    try:
        out = probe(a.proc, a.chain_id, a.key_types)
    except SeatKeyError as e:
        print(f"seat-keys: {e}", file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
