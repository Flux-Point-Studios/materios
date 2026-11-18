#!/usr/bin/env python3
"""Capture the settings a running materios-node process was started with, for the launch preflight.

    python3 capture_environ.py <pid> <out file>

Run on the validator's machine, as root or as the user the node runs as, with the node's own PID (the one whose
/proc/<pid>/cmdline and /proc/<pid>/stat are captured). It reads /proc/<pid>/environ, the environment the kernel
handed the process, and writes to <out file> only the settings CAPTURED names, each as NAME=value ended by a NUL, as
/proc lists them, then the process they were read from: its pid and its start, from /proc/<pid>/stat. A setting is
kept under any name the node's readers take for it (reads_as), spelled as the process has it. A database connection
string is written as <host>:<port>/<database>: no user, no password, no other parameter. A credential the node's
Postgres client reads is written as present, without its value. It prints the names it wrote and no value, and it
needs python3 alone: no package of the preflight's.

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
# What the follower's Postgres client, sqlx-postgres 0.7.4, reads for a connection besides its URL: where to connect
# and to which database when the URL leaves one out, as whom, over what TLS, and with which session options.
POSTGRES = ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGSSLMODE", "PGSSLROOTCERT",
            "PGSSLCERT", "PGSSLKEY", "PGAPPNAME", "PGOPTIONS")
CAPTURED = frozenset(FOLLOWER + PROPOSER + LOADER + POSTGRES)
CONNECTION_STRINGS = frozenset({"DB_SYNC_POSTGRES_CONNECTION_STRING"})
# Who the node connects to its database as, and with what: written as PRESENT, never by value.
CREDENTIALS = frozenset({"PGUSER", "PGPASSWORD", "PGPASSFILE", "PGSSLKEY"})
PRESENT = "<set>"
# The entry that ends a capture: the pid and the start, in clock ticks after boot, of the process it was read from.
PROCESS = "process"
POSTGRES_SCHEMES = ("postgres", "postgresql")
# The parameters of a connection URL that say where it connects, which the reduced form shows, and the ones that
# change what the session reads once it has, which the reduced form cannot show.
PLACE_PARAMETERS = {"host": "host", "hostaddr": "host", "port": "port", "dbname": "database"}
SESSION_PARAMETERS = "options"
# The characters of a host, a socket directory or a database name: none that a user, a password or a parameter is
# set apart by.
PLAIN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
HOST = PLAIN | frozenset(":/")


def reads_as(name: str) -> str:
    """The setting the most forgiving of the node's readers takes an environment name for. figment, through which
    the follower reads its database, its stability settings and Cardano's epoch layout, trims a name, matches it and
    the MC__ prefix whatever their ASCII case, trims again what follows the prefix, and nests a name at its first
    dot. A name this maps to another than itself is one the node may read where an exact-name reading does not."""
    name = name.strip().upper()
    if name.startswith("MC__"):
        name = "MC__" + name[len("MC__"):].strip()
    return name.split(".")[0].strip()


def reduced_connection(url: str) -> str:
    """<host>:<port>/<database> of a postgres:// URL, as sqlx reads it for the node. The URL must give each of the
    three once, itself or as a `host`, `hostaddr`, `port` or `dbname` parameter: one it leaves out comes from PGHOST,
    PGPORT or PGDATABASE, and of two sqlx keeps a socket over a host, whichever comes last. Session options, which
    can point every query at another schema, are refused, and so is an `@` after the host, where a password with a
    `/`, `?` or `#` in it would be read as a database, a parameter or a fragment."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in POSTGRES_SCHEMES or "@" in parts.path + parts.query + parts.fragment:
        raise ValueError("not a postgres URL the capture reads")
    given = {"host": [parts.hostname] if parts.hostname else [], "port": [parts.port] if parts.port else [],
             "database": [parts.path.lstrip("/")] if parts.path.lstrip("/") else []}
    for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        if name == SESSION_PARAMETERS or name.startswith(SESSION_PARAMETERS + "["):
            raise ValueError("session options")
        if name == "port" and not (value.isascii() and value.isdigit()):
            raise ValueError("a port that is no number")
        if name in PLACE_PARAMETERS:
            given[PLACE_PARAMETERS[name]].append(int(value) if name == "port" else value)
    if any(len(values) != 1 for values in given.values()):
        raise ValueError("no host, port or database, or one of them twice")
    (host,), (port,), (database,) = given.values()
    if not host or not database or not set(host) <= HOST or not set(database) <= PLAIN:
        raise ValueError("a host or database the capture does not write")
    return f"{f'[{host}]' if ':' in host else host}:{port}/{database}"


def captured(environ: bytes) -> dict[str, str]:
    """The settings of a /proc/<pid>/environ block that the node reads as one CAPTURED names, each under the name
    the process has it. An error names a setting, never a value."""
    settings = {}
    for entry in environ.split(b"\0"):
        name, given, value = entry.decode("utf-8", errors="surrogateescape").partition("=")
        setting = reads_as(name)
        if not given or setting not in CAPTURED:
            continue
        if name in settings:
            raise ValueError(f"{name} is set twice: the capture cannot tell which the node reads")
        if setting in CONNECTION_STRINGS:
            try:
                value = reduced_connection(value)
            except ValueError:
                raise ValueError(f"{name} is not a postgres:// URL that names its host, port and database, so it "
                                 "cannot be reduced to <host>:<port>/<database>; its value is not shown") from None
        settings[name] = PRESENT if setting in CREDENTIALS else value
    return settings


def process_of(stat: bytes) -> tuple[int, int]:
    """The pid and the start, in clock ticks after boot, that a /proc/<pid>/stat gives: its first field, and the
    20th after the command name, which stands in parentheses and may hold any character."""
    pid, _, _ = stat.partition(b" ")
    rest = stat.rpartition(b")")[2]
    fields = rest[1:-1].split(b" ")
    if not (pid.isdigit() and rest.startswith(b" ") and rest.endswith(b"\n") and len(fields) > 19
            and fields[19].isdigit()):
        raise ValueError("not a /proc/<pid>/stat")
    return int(pid), int(fields[19])


def written(settings: dict[str, str], process: tuple[int, int]) -> bytes:
    """A capture: each setting as NAME=value ended by a NUL, in the order of their names, then the process."""
    entries = [f"{name}={value}" for name, value in sorted(settings.items())]
    return b"".join(entry.encode("utf-8", errors="surrogateescape") + b"\0"
                    for entry in [*entries, f"{PROCESS}={process[0]} {process[1]}"])


def read(capture: bytes) -> tuple[dict[str, str], tuple[int, int]]:
    """The settings a capture holds and the process it was read from. Anything `written` would not write is refused:
    no process at its end, a setting the node reads as none CAPTURED names, one given twice, a credential by value,
    or a connection string that is not reduced, as a raw copy of /proc/<pid>/environ holds them."""
    if not capture.endswith(b"\0"):
        raise ValueError("it does not end each entry with a NUL")
    *entries, last = capture[:-1].split(b"\0")
    name, _, process = last.decode("utf-8").partition("=")
    pid, _, start = process.partition(" ")
    if name != PROCESS or not (pid.isascii() and pid.isdigit() and start.isascii() and start.isdigit()):
        raise ValueError("it does not end with the process it was read from")
    settings = {}
    for entry in entries:
        name, given, value = entry.decode("utf-8").partition("=")
        setting = reads_as(name)
        if not given or setting not in CAPTURED or name in settings:
            raise ValueError("it holds an entry that is no setting the capture writes, or one twice")
        if setting in CONNECTION_STRINGS and not connection_is_reduced(value):
            raise ValueError(f"its {setting} is not reduced to <host>:<port>/<database>")
        if setting in CREDENTIALS and value != PRESENT:
            raise ValueError(f"it shows the value of {setting}")
        settings[name] = value
    return settings, (int(pid), int(start))


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
        with open(f"/proc/{args.pid}/stat", "rb") as stat:
            process = process_of(stat.read())
        with open(f"/proc/{args.pid}/environ", "rb") as environ:
            settings = captured(environ.read())
        with open(f"/proc/{args.pid}/stat", "rb") as stat:
            if process_of(stat.read()) != process:
                raise ValueError(f"pid {args.pid} became another process while it was read: run the capture again")
        with open(args.out, "wb") as out:
            out.write(written(settings, process))
    except (OSError, ValueError) as e:
        print(e, file=sys.stderr)
        return 1
    print(f"pid {args.pid}: {len(settings)} settings written to {args.out}: {' '.join(sorted(settings))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
