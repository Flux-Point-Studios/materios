#!/usr/bin/env python3
"""Capture the settings a running materios-node process was started with, for the launch preflight.

    python3 capture_environ.py <pid> <out file>

Run on the validator's machine, as root or as the user the node runs as, with the node's own PID (the one whose
/proc/<pid>/cmdline is captured). It reads /proc/<pid>/environ, the environment the kernel handed the process, and
writes to <out file> only the settings CAPTURED names, each as NAME=value ended by a NUL, as /proc lists them. A
database connection string is written as <host>:<port>/<database>: no user, no password, no other parameter. It
prints the names it wrote and no value, and it needs python3 alone: no package of the preflight's.

The preflight reads an authority's capture next to its cmdline capture, at <cmdline capture>.environ.
"""
from __future__ import annotations

import argparse
import sys
import urllib.parse

# The node's Cardano follower: the mock switch and its registrations file, which no authority may run with, the
# backend, its database and how deep it waits, Cardano's epoch layout and stability parameters, and what the
# yaci-store backend reads for stake snapshots, the program it runs among them.
FOLLOWER = ("USE_MAIN_CHAIN_FOLLOWER_MOCK", "MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE", "MAIN_CHAIN_FOLLOWER",
            "DB_SYNC_POSTGRES_CONNECTION_STRING", "BLOCK_STABILITY_MARGIN", "CARDANO_SECURITY_PARAMETER",
            "CARDANO_ACTIVE_SLOTS_COEFF", "MC__FIRST_EPOCH_TIMESTAMP_MILLIS", "MC__EPOCH_DURATION_MILLIS",
            "MC__FIRST_EPOCH_NUMBER", "MC__FIRST_SLOT_NUMBER", "MC__SLOT_DURATION_MILLIS",
            "MITHRIL_AGGREGATOR_ENDPOINT", "MITHRIL_GENESIS_VERIFICATION_KEY", "MITHRIL_CLIENT_BIN")
# What the block proposer counts the node's blocks under.
PROPOSER = ("SIDECHAIN_BLOCK_BENEFICIARY",)
# What the dynamic loader runs or links into the node before its own code.
LOADER = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")
CAPTURED = frozenset(FOLLOWER + PROPOSER + LOADER)
CONNECTION_STRINGS = frozenset({"DB_SYNC_POSTGRES_CONNECTION_STRING"})
POSTGRES_SCHEMES = ("postgres", "postgresql")
# The characters of a host, a socket directory or a database name: none that a user, a password or a parameter is
# set apart by.
PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
HOST = PLAIN | frozenset(":/")


def reduced_connection(url: str) -> str:
    """<host>:<port>/<database> of a postgres:// URL, as sqlx reads it for the node: the host, port and database of
    the URL itself, each replaced by the `host`, `hostaddr`, `port` or `dbname` parameter that follows it. A URL that
    leaves one out takes it from PGHOST, PGPORT or PGDATABASE, which the capture does not read, so it is refused."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in POSTGRES_SCHEMES:
        raise ValueError("not a postgres URL")
    host, port, database = parts.hostname, parts.port, parts.path.lstrip("/")
    for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if name in ("host", "hostaddr"):
            host = value
        elif name == "port":
            port = int(value)
        elif name == "dbname":
            database = value
    if not host or port is None or not database or not set(host) <= HOST or not set(database) <= PLAIN:
        raise ValueError("no host, port or database")
    return f"{f'[{host}]' if ':' in host else host}:{port}/{database}"


def captured(environ: bytes) -> dict[str, str]:
    """The settings of a /proc/<pid>/environ block that CAPTURED names, in any case: the node's follower reads its
    settings whatever their case, so each is kept as the process has it. An error names a setting, never a value."""
    settings = {}
    for entry in environ.split(b"\0"):
        name, given, value = entry.decode("utf-8", errors="surrogateescape").partition("=")
        if not given or name.upper() not in CAPTURED:
            continue
        if name in settings:
            raise ValueError(f"{name} is set twice: the capture cannot tell which the node reads")
        if name.upper() in CONNECTION_STRINGS:
            try:
                value = reduced_connection(value)
            except ValueError:
                raise ValueError(f"{name} is not a postgres:// URL that names its host, port and database, so it "
                                 "cannot be reduced to <host>:<port>/<database>; its value is not shown") from None
        settings[name] = value
    return settings


def written(settings: dict[str, str]) -> bytes:
    """A capture: each setting as NAME=value ended by a NUL, in the order of their names."""
    return b"".join(f"{name}={value}".encode("utf-8", errors="surrogateescape") + b"\0"
                    for name, value in sorted(settings.items()))


def read(capture: bytes) -> dict[str, str]:
    """The settings a capture holds. Anything `written` would not write is refused: a setting CAPTURED does not name,
    one given twice, or a connection string that is not reduced, as a raw copy of /proc/<pid>/environ holds them."""
    if capture and not capture.endswith(b"\0"):
        raise ValueError("it does not end each setting with a NUL")
    settings = {}
    for entry in capture.split(b"\0")[:-1]:
        name, given, value = entry.decode("utf-8").partition("=")
        if not given or name.upper() not in CAPTURED or name in settings:
            raise ValueError("it holds an entry that is no setting the capture writes, or one twice")
        if name.upper() in CONNECTION_STRINGS and not connection_is_reduced(value):
            raise ValueError(f"its {name} is not reduced to <host>:<port>/<database>")
        settings[name] = value
    return settings


def connection_is_reduced(value: str) -> bool:
    """Whether `value` is <host>:<port>/<database> as reduced_connection writes it."""
    address, _, database = value.rpartition("/")
    host, _, port = address.rpartition(":")
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    return bool(bare and database) and set(bare) <= HOST and set(database) <= PLAIN and port.isdigit() \
        and (":" not in bare or host.startswith("["))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pid", type=int, help="the node process whose /proc/<pid>/environ is read")
    parser.add_argument("out", help="where the capture is written: <the authority's cmdline capture>.environ")
    args = parser.parse_args(argv)
    try:
        with open(f"/proc/{args.pid}/environ", "rb") as environ:
            settings = captured(environ.read())
        with open(args.out, "wb") as out:
            out.write(written(settings))
    except (OSError, ValueError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"pid {args.pid}: {len(settings)} settings written to {args.out}: {' '.join(sorted(settings))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
