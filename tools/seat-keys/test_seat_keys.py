"""Tests for the seat-key probe.

Each test builds a fake /proc and a fake host filesystem under tmp_path, so the
probe finds a node, the chain it runs and its keystore exactly as it does on a
validator host: through the process's argv, its open files, and its own root and
working directory.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import seat_keys as sk

HERE = Path(__file__).resolve().parent
AURA_A = "11" * 32
AURA_B = "2a" * 32
GRAN_A = "3c" * 32
CHAIN_ID = "materios_preprod_v6"
BASE = "/srv/materios/data"
CONFIG_DIR = f"{BASE}/chains/{CHAIN_ID}"
KEYSTORE = f"{CONFIG_DIR}/keystore"
SPEC = "/srv/materios/chain-spec-v6-raw.json"


class Host:
    """A fake host: a filesystem root and a /proc holding the processes on it."""

    def __init__(self, tmp_path: Path):
        self.fs = tmp_path / "fs"
        self.proc = tmp_path / "proc"
        self.fs.mkdir()
        self.proc.mkdir()

    def file(self, path: str, text: str = "", root: Path | None = None) -> Path:
        p = (self.fs if root is None else root) / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def key(self, keystore: str, key_type: str, public: str, root: Path | None = None) -> Path:
        return self.file(f"{keystore}/{key_type.encode().hex()}{public}", '"secret, never read"', root)

    def process(self, pid: int, argv: list[str | bytes], *, databases: tuple[str, ...] = (CONFIG_DIR,),
                files: tuple[str, ...] = (), cwd: str = "/", root: Path | None = None) -> Path:
        """A process with its argv, root and working directory, holding open the databases under each config dir and
        any other files as the kernel names them: canonical paths in the process's own root."""
        d = self.proc / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(a if isinstance(a, bytes) else a.encode() for a in argv) + b"\0")
        base = self.fs if root is None else root
        (d / "root").symlink_to(base)
        (d / "cwd").symlink_to(base / cwd.lstrip("/"))
        fd = d / "fd"
        fd.mkdir()
        # Paths that only look like a database: a "db" two steps below another directory, a "chains" directory.
        links = ["/dev/null", "socket:[5150]", "anon_inode:[eventpoll]", "/var/log/materios/db/node.log",
                 "/srv/chains/backup/2026.tar", *files]
        for config_dir in databases:
            links += [f"{config_dir}/db/full/LOCK", f"{config_dir}/db/full/000042.log",
                      f"{config_dir}/db/full/000041.sst (deleted)"]
        for n, link in enumerate(links):
            (fd / str(n)).symlink_to(link)
        return d

    def probe(self, *key_types: str, chain_id: str = CHAIN_ID) -> dict:
        return sk.probe(self.proc, chain_id, list(key_types))


def validator_argv(*extra: str, flag: str = "--validator") -> list[str]:
    return ["/usr/local/bin/materios-node-spo", "--chain", SPEC, flag, "--base-path", BASE, *extra]


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


def test_key_type_hex_matches_the_sdk_file_name_prefix():
    # sc-keystore names a key file hex(key type) + hex(public) (local.rs key_file_path).
    assert sk.key_type_hex("aura") == "61757261"
    assert sk.key_type_hex("gran") == "6772616e"


@pytest.mark.parametrize("key_type", ["aur", "auraa", "äura", ""])
def test_a_key_type_that_is_not_four_ascii_bytes_refuses(key_type):
    with pytest.raises(sk.SeatKeyError, match=f"^key type {key_type!r} is not 4 ASCII bytes$"):
        sk.key_type_hex(key_type)


@pytest.mark.parametrize("form", [
    ["--base-path", BASE],
    [f"--base-path={BASE}"],
    ["-d", BASE],
    [f"-d{BASE}"],
    [f"-d={BASE}"],
])
def test_held_keys_come_from_the_keystore_under_the_base_path_and_running_chain(host, form):
    host.key(KEYSTORE, "aura", AURA_A)
    host.key(KEYSTORE, "gran", GRAN_A)
    host.process(4242, ["/usr/local/bin/materios-node-spo", "--chain", SPEC, "--validator", *form])
    assert host.probe("aura", "gran") == {"pid": 4242, "chain_id": CHAIN_ID, "keystore": KEYSTORE,
                                          "held": {"aura": ["0x" + AURA_A], "gran": ["0x" + GRAN_A]}}


@pytest.mark.parametrize("chain", [SPEC, "preprod"])
def test_the_chain_is_the_one_whose_database_the_node_holds_open(host, chain):
    # The node read its spec once, at its start. The file its --chain names now holds another chain's spec, and a
    # spec built into the node has no file at all: neither says which keystore the node reads.
    host.file(SPEC, json.dumps({"id": "materios_preprod_v5"}))
    host.key(f"{BASE}/chains/materios_preprod_v5/keystore", "aura", AURA_B)
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, ["materios-node", "--chain", chain, "--validator", "--base-path", BASE])
    out = host.probe("aura")
    assert out["keystore"] == KEYSTORE
    assert out["held"] == {"aura": ["0x" + AURA_A]}
    with pytest.raises(sk.SeatKeyError, match="0 authority processes run chain materios_preprod_v5"):
        host.probe("aura", chain_id="materios_preprod_v5")


def test_keystore_path_overrides_the_base_path(host):
    host.key("/keys/custom", "aura", AURA_B)
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--keystore-path", "/keys/custom"))
    out = host.probe("aura")
    assert out["keystore"] == "/keys/custom"
    assert out["held"] == {"aura": ["0x" + AURA_B]}


def test_relative_paths_resolve_against_the_node_working_directory(host):
    host.key(f"/srv/node/data/chains/{CHAIN_ID}/keystore", "aura", AURA_A)
    host.key(KEYSTORE, "aura", AURA_B)
    host.process(1, ["materios-node", "--validator", "--base-path", "data"], cwd="/srv/node",
                 databases=(f"/srv/node/data/chains/{CHAIN_ID}",))
    out = host.probe("aura")
    assert out["keystore"] == f"data/chains/{CHAIN_ID}/keystore"
    assert out["held"] == {"aura": ["0x" + AURA_A]}


def test_absolute_paths_resolve_inside_the_node_root(host, tmp_path):
    # A containerised node's /data is not the host's /data.
    container = tmp_path / "container"
    host.key(f"/data/chains/{CHAIN_ID}/keystore", "aura", AURA_B, root=container)
    host.key(f"/data/chains/{CHAIN_ID}/keystore", "aura", AURA_A)
    host.process(7, ["/usr/local/bin/materios-node", "--chain", "/chain-spec/chain-spec-raw.json", "--validator",
                     "--base-path", "/data"], root=container, databases=(f"/data/chains/{CHAIN_ID}",))
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_B]}


@pytest.mark.parametrize("link, target, argv", [
    # An absolute link the node follows from its own root, and the kernel would follow from the probe's.
    ("/srv/materios/data", "/srv/elsewhere", validator_argv()),
    ("/srv/materios", "/srv/elsewhere", validator_argv()),
    (KEYSTORE, "../materios_preprod_v5/keystore", validator_argv()),
    ("/keys", "/srv/elsewhere", validator_argv("--keystore-path", "/keys/custom")),
    ("/srv/node/data", "/srv/elsewhere", ["materios-node", "--validator", "--base-path", "data"]),
])
def test_a_symbolic_link_on_the_keystore_path_refuses(host, link, target, argv):
    host.key(f"/srv/elsewhere/chains/{CHAIN_ID}/keystore", "aura", AURA_A)
    host.key("/srv/elsewhere/custom", "aura", AURA_A)
    if link == KEYSTORE:
        host.key(f"{BASE}/chains/materios_preprod_v5/keystore", "aura", AURA_A)
    path = host.fs / link.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    host.process(1, argv, cwd="/srv/node")
    with pytest.raises(sk.SeatKeyError, match=f"{link.lstrip('/').split('/')[-1]}, on the keystore path .* is a "
                                              "symbolic link"):
        host.probe("aura")


def test_a_keystore_path_that_climbs_refuses(host):
    host.key("/keys/custom", "aura", AURA_A)
    host.process(1, validator_argv("--keystore-path", "/srv/../keys/custom"))
    with pytest.raises(sk.SeatKeyError, match=r"climbs with '\.\.'"):
        host.probe("aura")


def test_every_key_entry_counts_as_held_whatever_the_node_can_open(host):
    # The probe cannot judge what the node can open (its fsuid, groups, capabilities, ACLs, security modules), so it
    # reports every entry the node may load: a key the node holds is never missing from `held`.
    ks = host.fs / KEYSTORE.lstrip("/")
    host.key(KEYSTORE, "aura", AURA_A).chmod(0)
    (ks / ("61757261" + AURA_B)).symlink_to(host.fs / "gone")
    (ks / ("61757261" + GRAN_A)).mkdir()
    (ks / ("61757261" + "44" * 32)).symlink_to(host.key("/srv/other", "aura", "55" * 32))
    host.process(1, validator_argv())
    out = host.probe("aura")
    assert out["held"] == {"aura": sorted("0x" + k for k in (AURA_A, AURA_B, GRAN_A, "44" * 32))}
    assert set(out) == {"pid", "chain_id", "keystore", "held"}


def test_only_lowercase_hex_names_of_the_asked_type_count(host):
    every_digit = "0123456789abcdef" * 4
    host.key(KEYSTORE, "aura", every_digit)
    host.key(KEYSTORE, "aura", AURA_A)
    host.key(KEYSTORE, "gran", GRAN_A)
    host.file(f"{KEYSTORE}/61757261{AURA_B.upper()}")
    host.file(f"{KEYSTORE}/61757261zz")
    host.file(f"{KEYSTORE}/61757261a")
    host.file(f"{KEYSTORE}/61757261")
    host.file(f"{KEYSTORE}/6175726")
    host.file(f"{KEYSTORE}/README")
    host.process(1, validator_argv())
    assert host.probe("aura")["held"] == {"aura": ["0x" + every_digit, "0x" + AURA_A]}


def opened_path(path, dir_fd=None) -> str:
    if isinstance(path, int):
        return os.readlink(f"/proc/self/fd/{path}")
    if dir_fd is not None and not os.path.isabs(path):
        path = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), path)
    return os.path.realpath(path)


@pytest.mark.parametrize("opener", ["builtins.open", "io.open", "os.open"])
def test_the_probe_never_opens_a_key_file(host, monkeypatch, opener):
    key = os.path.realpath(host.key(KEYSTORE, "aura", AURA_A))
    host.process(1, validator_argv())
    module, name = opener.rsplit(".", 1)
    real = getattr(sys.modules[module], name)

    def guarded(path, *a, **kw):
        if isinstance(path, (str, bytes, os.PathLike)):
            assert opened_path(os.fsdecode(path), kw.get("dir_fd")) != key, "the probe opened a key file"
        return real(path, *a, **kw)

    monkeypatch.setattr(opener, guarded)
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_A]}


@pytest.mark.parametrize("argv", [
    ["/opt/node/run", "--chain", SPEC, "--validator", "--base-path", BASE],
    ["materios-node", "--validator", "--base-path", BASE],
    ["materios-node", "--chain=preprod", "--validator", "--base-path", BASE],
])
def test_an_authority_is_any_process_with_an_authority_flag_on_the_chain(host, argv):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(31, argv)
    assert host.probe("aura") == {"pid": 31, "chain_id": CHAIN_ID, "keystore": KEYSTORE,
                                  "held": {"aura": ["0x" + AURA_A]}}


def test_full_nodes_and_authorities_on_other_chains_are_not_probed(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(2, [b"/usr/bin/materios-node", b"--name", b"\xffnode", b"--base-path", b"/srv/other"])
    host.process(5150, ["/usr/local/bin/materios-node", "--chain", "/chain-spec/chain-spec-raw.json",
                        "--validator", "--base-path", "/data"], databases=("/data/chains/materios_preprod_v5",))
    host.process(6161, validator_argv())
    host.process(6162, ["materios-node-spo", "--chain", SPEC, "--base-path", "/srv/full"],
                 databases=(f"/srv/full/chains/{CHAIN_ID}",))
    host.process(5, ["/usr/bin/bash", "-lc", f"materios-node --validator --chain {SPEC}"], databases=())
    host.process(6, ["/usr/bin/python3", "-", "--chain-id", CHAIN_ID, "aura"], databases=())
    assert host.probe("aura")["pid"] == 6161


@pytest.mark.parametrize("second", ["--validator", "--bob", "--dev"])
def test_two_authority_processes_on_the_chain_refuse(host, second):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv())
    host.process(2, ["/opt/other/node", "--base-path", "/srv/b", second], databases=(f"/srv/b/chains/{CHAIN_ID}",))
    with pytest.raises(sk.SeatKeyError, match=f"2 authority processes run chain {CHAIN_ID}; expected exactly 1"):
        host.probe("aura")


def test_no_authority_process_on_the_chain_refuses(host):
    host.process(1, ["materios-node", "--chain", SPEC, "--base-path", BASE])
    with pytest.raises(sk.SeatKeyError, match=f"0 authority processes run chain {CHAIN_ID}"):
        host.probe("aura")


@pytest.mark.parametrize("databases, held", [
    ((), "no chain database"),
    ((CONFIG_DIR, f"{BASE}/chains/materios_preprod_v5"), "2 chains' databases"),
])
def test_an_authority_whose_chain_cannot_be_told_refuses(host, databases, held):
    # A wrapper that execs nothing (timeout, sudo) passes the flag on its own argv; a node on another chain might be
    # this one's double. Either may be the validator the probe was asked about, so it gives no answer.
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv())
    host.process(9, ["/usr/bin/timeout", "900", "materios-node", "--validator"], databases=databases)
    with pytest.raises(sk.SeatKeyError, match=f"process 9 \\(timeout\\) runs with an authority flag and holds {held} "
                                              "open"):
        host.probe("aura")


def test_a_node_on_paritydb_holding_only_its_database_directory_is_found(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--database", "paritydb"), databases=(), files=(f"{CONFIG_DIR}/paritydb",))
    assert host.probe("aura")["pid"] == 1


def test_an_authority_whose_open_files_cannot_be_read_refuses(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv())
    d = host.process(9, validator_argv(), databases=())
    shutil.rmtree(d / "fd")
    (d / "fd").write_text("")
    with pytest.raises(sk.SeatKeyError, match="^cannot read the open files of process 9: Not a directory; run the "
                                              "probe as the node's user or root$"):
        host.probe("aura")


def test_an_argv_that_cannot_be_read_refuses(host):
    host.process(1, validator_argv())
    (host.proc / "7").mkdir()
    (host.proc / "7" / "cmdline").mkdir()
    with pytest.raises(sk.SeatKeyError, match="^cannot read the argv of process 7: Is a directory$"):
        host.probe("aura")


def test_a_process_that_exits_meanwhile_is_skipped(host):
    host.key(KEYSTORE, "aura", AURA_A)
    (host.proc / "1").mkdir()
    host.process(2, validator_argv())
    assert host.probe("aura")["pid"] == 2


def test_a_file_the_node_closes_meanwhile_is_skipped(host, monkeypatch):
    host.key(KEYSTORE, "aura", AURA_A)
    fd = host.process(1, validator_argv()) / "fd"
    listdir, readlink = os.listdir, os.readlink
    monkeypatch.setattr(os, "listdir", lambda p: sorted(listdir(p), key=int) if p == fd else listdir(p))

    def closed_first(path, *a, **kw):
        if path == fd / "0":
            raise FileNotFoundError(2, "No such file or directory")
        return readlink(path, *a, **kw)

    monkeypatch.setattr(os, "readlink", closed_first)
    assert host.probe("aura")["pid"] == 1


def test_a_node_root_the_probe_cannot_open_refuses(host):
    d = host.process(1, validator_argv())
    (d / "root").unlink()
    (d / "root").symlink_to(host.fs / "gone")
    with pytest.raises(sk.SeatKeyError, match="^cannot open the root of process 1: No such file or directory; run "
                                              "the probe as the node's user or root$"):
        host.probe("aura")


@pytest.mark.parametrize("swap, reason", [
    ("link", "(Not a directory|Too many levels of symbolic links)"),
    ("file", "Not a directory"),
])
def test_a_step_swapped_after_its_check_refuses(host, monkeypatch, swap, reason):
    # Between the probe's lstat of a step and its open, the step becomes a link or a file. The open itself refuses
    # to follow the one or enter the other; which error a link gets depends on the kernel.
    ks = host.fs / KEYSTORE.lstrip("/")
    ks.parent.mkdir(parents=True)
    if swap == "link":
        host.key("/srv/elsewhere", "aura", AURA_A)
        ks.symlink_to(host.fs / "srv" / "elsewhere")
    else:
        ks.write_text("")
    host.process(1, validator_argv())
    real_stat = os.stat
    monkeypatch.setattr(os, "stat", lambda p, *a, **kw: real_stat(host.fs) if p == "keystore" else real_stat(p, *a,
                                                                                                             **kw))
    with pytest.raises(sk.SeatKeyError, match=f"^cannot open {KEYSTORE.lstrip('/')}, on the keystore path "
                                              f"{KEYSTORE}: {reason}$"):
        host.probe("aura")


@pytest.mark.parametrize("flags", [[flag] for flag in sorted(sk.KEYRING_FLAGS)] + [["--dev", "--alice"]])
def test_a_node_with_dev_keys_in_memory_refuses(host, flags):
    # A keyring flag puts a dev seed's keys in a map has_keys checks before any file (local.rs:512-515).
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv(*flags[1:], flag=flags[0]))
    with pytest.raises(sk.SeatKeyError, match=f"^the node runs with {' '.join(sorted(flags))}, which keeps a dev "
                                              "seed's keys in memory, where no file shows them$"):
        host.probe("aura")


@pytest.mark.parametrize("argv, reason", [
    (["materios-node", "--validator"],
     "^the node runs with no --base-path, so it uses a platform default this probe does not guess$"),
    (validator_argv("--tmp"), r"^the node keeps its keystore in a temporary base path \(--tmp\)$"),
    (validator_argv("-d", "/b"), "--base-path is given more than once"),
    (validator_argv("--keystore-path", "/k", "--keystore-path=/j"), "--keystore-path is given more than once"),
    (validator_argv("--keystore-path"), "--keystore-path has no value"),
])
def test_an_unresolvable_keystore_refuses(host, argv, reason):
    host.process(1, argv)
    with pytest.raises(sk.SeatKeyError, match=reason):
        host.probe("aura")


@pytest.mark.parametrize("make, reason", [
    (lambda h: h.file(SPEC), f"no keystore at {KEYSTORE}: srv/materios/data does not exist"),
    (lambda h: h.file(KEYSTORE), f"keystore, on the keystore path {KEYSTORE}, is not a directory"),
])
def test_a_keystore_that_is_not_a_directory_refuses(host, make, reason):
    make(host)
    host.process(1, validator_argv())
    with pytest.raises(sk.SeatKeyError, match=reason):
        host.probe("aura")


def test_a_host_without_proc_refuses(tmp_path):
    with pytest.raises(sk.SeatKeyError, match="reads Linux's /proc"):
        sk.probe(tmp_path / "no-proc", CHAIN_ID, ["aura"])


def run_main(host: Host, monkeypatch, capsys, *args: str) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["seat_keys.py", "--proc", str(host.proc), "--chain-id", CHAIN_ID, *args])
    code = sk.main()
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_prints_the_probe_as_json(host, monkeypatch, capsys):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv())
    code, out, err = run_main(host, monkeypatch, capsys, "aura", "gran")
    assert (code, err) == (0, "")
    assert json.loads(out) == {"pid": 1, "chain_id": CHAIN_ID, "keystore": KEYSTORE,
                               "held": {"aura": ["0x" + AURA_A], "gran": []}}


@pytest.mark.parametrize("argv, key_type, reason", [
    (["materios-node", "--validator"], "aura",
     "the node runs with no --base-path, so it uses a platform default this probe does not guess"),
    (validator_argv(), "aur", "key type 'aur' is not 4 ASCII bytes"),
])
def test_cli_refusal_exits_2_with_the_reason(host, monkeypatch, capsys, argv, key_type, reason):
    host.process(1, argv)
    assert run_main(host, monkeypatch, capsys, key_type) == (2, "", f"seat-keys: {reason}\n")


def test_cli_reads_the_host_proc_unless_told_otherwise(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(sk, "probe", lambda proc, chain_id, key_types: seen.append((proc, chain_id, key_types)) or {})
    for args in (["--chain-id", CHAIN_ID, "aura"], ["--proc", "/elsewhere", "--chain-id", CHAIN_ID, "aura", "gran"]):
        monkeypatch.setattr(sys, "argv", ["seat_keys.py", *args])
        assert sk.main() == 0
    assert seen == [(Path("/proc"), CHAIN_ID, ["aura"]), (Path("/elsewhere"), CHAIN_ID, ["aura", "gran"])]
    assert all(type(proc) is type(Path()) for proc, _, _ in seen)


def test_cli_requires_a_chain_id(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["seat_keys.py", "aura"])
    with pytest.raises(SystemExit) as e:
        sk.main()
    assert e.value.code == 2
    assert "the following arguments are required: --chain-id" in capsys.readouterr().err


def test_cli_help_says_what_each_argument_takes(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["seat_keys.py", "--help"])
    with pytest.raises(SystemExit):
        sk.main()
    text = " ".join(capsys.readouterr().out.split())
    for said in ("List the session keys a running validator's keystore holds.",
                 "--chain-id CHAIN_ID the id of the chain spec the validator runs, e.g. materios_preprod_v6",
                 "key_types 4-byte key types, e.g. aura gran"):
        assert f" {said} " in f" {text} "


def test_cli_over_stdin_prints_the_probe_as_json(host):
    # The ceremony ships this file to each host as `ssh host python3 - ARGS` with the source on stdin.
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv())
    r = subprocess.run([sys.executable, "-", "--proc", str(host.proc), "--chain-id", CHAIN_ID, "aura"],
                       input=(HERE / "seat_keys.py").read_text(), capture_output=True, text=True, check=False, cwd="/")
    assert (r.returncode, r.stderr) == (0, "")
    assert json.loads(r.stdout)["held"] == {"aura": ["0x" + AURA_A]}


def test_python_older_than_3_10_is_refused_before_it_crashes():
    source = HERE / "seat_keys.py"
    run_as_3_9 = ("import sys; sys.version_info = (3, 9, 18, 'final', 0); "
                  f"exec(compile(open({str(source)!r}).read(), 'seat_keys.py', 'exec'), {{'__name__': '__main__'}})")
    r = subprocess.run([sys.executable, "-c", run_as_3_9, "--chain-id", CHAIN_ID, "aura"], capture_output=True,
                       text=True, check=False)
    assert (r.returncode, r.stdout) == (2, "")
    assert r.stderr == "seat-keys: needs Python 3.10 or newer\n"
