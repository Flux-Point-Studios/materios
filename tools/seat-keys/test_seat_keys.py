"""Tests for the seat-key probe.

Each test builds a fake /proc and a fake host filesystem under tmp_path, so the
probe resolves a keystore exactly as it does on a validator host, through the
process's own root and working directory.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import seat_keys as sk

HERE = Path(__file__).resolve().parent
AURA_A = "11" * 32
AURA_B = "2a" * 32
GRAN_A = "3c" * 32
SPEC_ID = "materios_preprod_v6"
SUFFIX = "chain-spec-v6-raw.json"


class Host:
    """A fake host: a filesystem root and a /proc holding the processes on it."""

    def __init__(self, tmp_path: Path):
        self.fs = tmp_path / "fs"
        self.proc = tmp_path / "proc"
        self.fs.mkdir()
        self.proc.mkdir()

    def file(self, path: str, text: str = "") -> Path:
        p = self.fs / path.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def spec(self, path: str, spec_id: str = SPEC_ID) -> None:
        self.file(path, json.dumps({"name": "Materios Preprod", "id": spec_id, "genesis": {"raw": {}}}))

    def key(self, keystore: str, key_type: str, public: str) -> Path:
        return self.file(f"{keystore}/{key_type.encode().hex()}{public}", '"secret, never read"')

    def process(self, pid: int, argv: list[str], *, cwd: str = "/", uid: int | None = None,
                root: Path | None = None) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        euid = os.geteuid() if uid is None else uid
        (d / "status").write_text(f"Name:\tmaterios-node\nUid:\t{euid}\t{euid}\t{euid}\t{euid}\n")
        base = self.fs if root is None else root
        (d / "root").symlink_to(base)
        (d / "cwd").symlink_to(base / cwd.lstrip("/"))

    def probe(self, *key_types: str) -> dict:
        return sk.probe(self.proc, SUFFIX, list(key_types))


def validator_argv(*extra: str) -> list[str]:
    return ["/usr/local/bin/materios-node-spo", "--chain", f"/srv/materios/{SUFFIX}",
            "--validator", *extra]


@pytest.fixture
def host(tmp_path):
    h = Host(tmp_path)
    h.spec(f"/srv/materios/{SUFFIX}")
    return h


KEYSTORE = f"/srv/materios/data/chains/{SPEC_ID}/keystore"


def test_key_type_hex_matches_the_sdk_file_name_prefix():
    # sc-keystore names a key file hex(key type) + hex(public) (local.rs key_file_path).
    assert sk.key_type_hex("aura") == "61757261"
    assert sk.key_type_hex("gran") == "6772616e"


@pytest.mark.parametrize("form", [
    ["--base-path", "/srv/materios/data"],
    ["--base-path=/srv/materios/data"],
    ["-d", "/srv/materios/data"],
    ["-d/srv/materios/data"],
    ["-d=/srv/materios/data"],
])
def test_held_keys_come_from_the_keystore_under_the_base_path_and_spec_id(host, form):
    host.key(KEYSTORE, "aura", AURA_A)
    host.key(KEYSTORE, "gran", GRAN_A)
    host.process(4242, validator_argv(*form))
    out = host.probe("aura", "gran")
    assert out["pid"] == 4242
    assert out["keystore"] == KEYSTORE
    assert out["held"] == {"aura": ["0x" + AURA_A], "gran": ["0x" + GRAN_A]}
    assert out["unreadable"] == {"aura": [], "gran": []}


def test_a_keystore_under_another_chain_id_is_not_held(host):
    # A keystore left from an earlier chain id sits beside the live one; the node reads only its spec's id.
    host.key("/srv/materios/data/chains/materios_preprod_v5/keystore", "aura", AURA_B)
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_A]}


def test_keystore_path_overrides_the_base_path(host):
    host.key("/keys/custom", "aura", AURA_B)
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--base-path", "/srv/materios/data",
                                   "--keystore-path", "/keys/custom"))
    out = host.probe("aura")
    assert out["keystore"] == "/keys/custom"
    assert out["held"] == {"aura": ["0x" + AURA_B]}


def test_relative_paths_resolve_against_the_node_working_directory(host):
    host.spec(f"/srv/node/{SUFFIX}")
    host.key(f"/srv/node/data/chains/{SPEC_ID}/keystore", "aura", AURA_A)
    host.process(1, ["materios-node", "--chain", SUFFIX, "--validator", "--base-path", "data"], cwd="/srv/node")
    out = host.probe("aura")
    assert out["keystore"] == f"data/chains/{SPEC_ID}/keystore"
    assert out["held"] == {"aura": ["0x" + AURA_A]}


def test_absolute_paths_resolve_inside_the_node_root(host, tmp_path):
    # A containerised node's /data is not the host's /data.
    container = tmp_path / "container"
    (container / "chain-spec").mkdir(parents=True)
    (container / "chain-spec" / SUFFIX).write_text(json.dumps({"id": SPEC_ID}))
    ks = container / "data" / "chains" / SPEC_ID / "keystore"
    ks.mkdir(parents=True)
    (ks / ("61757261" + AURA_B)).write_text('"x"')
    host.key(f"/data/chains/{SPEC_ID}/keystore", "aura", AURA_A)
    host.process(7, ["/usr/local/bin/materios-node", "--chain", f"/chain-spec/{SUFFIX}", "--validator",
                     "--base-path", "/data"], root=container)
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_B]}


def test_only_lowercase_hex_names_of_the_asked_type_count(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.key(KEYSTORE, "gran", GRAN_A)
    host.file(f"{KEYSTORE}/61757261{AURA_B.upper()}")
    host.file(f"{KEYSTORE}/61757261zz")
    host.file(f"{KEYSTORE}/6175726")
    host.file(f"{KEYSTORE}/README")
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_A]}


def test_a_key_file_the_node_cannot_open_is_unreadable_not_held(host):
    host.key(KEYSTORE, "aura", AURA_A)
    (host.fs / KEYSTORE.lstrip("/") / ("61757261" + AURA_B)).symlink_to(host.fs / "gone")
    (host.fs / KEYSTORE.lstrip("/") / ("61757261" + GRAN_A)).mkdir()
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    out = host.probe("aura")
    assert out["held"] == {"aura": ["0x" + AURA_A]}
    assert out["unreadable"] == {"aura": sorted(["0x" + AURA_B, "0x" + GRAN_A])}


@pytest.mark.parametrize("opener", ["builtins.open", "io.open", "os.open"])
def test_the_probe_never_opens_a_key_file(host, monkeypatch, opener):
    key = os.path.realpath(host.key(KEYSTORE, "aura", AURA_A))
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    module, name = opener.rsplit(".", 1)
    real = getattr(sys.modules[module], name)

    def guarded(path, *a, **kw):
        if isinstance(path, (str, bytes, os.PathLike)):
            assert os.path.realpath(path) != key, "the probe opened a key file"
        return real(path, *a, **kw)

    monkeypatch.setattr(opener, guarded)
    assert host.probe("aura")["held"] == {"aura": ["0x" + AURA_A]}


def test_only_the_validator_on_the_named_chain_spec_is_probed(host):
    # A second, containerised materios-node runs another chain spec on the same host.
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(5150, ["/usr/local/bin/materios-node", "--chain", "/chain-spec/chain-spec-raw.json",
                        "--validator", "--base-path", "/data"])
    host.process(6161, validator_argv("--base-path", "/srv/materios/data"))
    host.process(5, ["/usr/bin/bash", "-lc", f"materios-node --validator --chain {SUFFIX}"])
    host.process(6, ["/usr/local/bin/materios-node-spo", "--chain", f"/x/{SUFFIX}", "--base-path", "/x"])
    assert host.probe("aura")["pid"] == 6161


@pytest.mark.parametrize("argv, reason", [
    (validator_argv(), "no --base-path"),
    (validator_argv("--tmp"), "temporary"),
    (validator_argv("--dev"), "temporary"),
    (["materios-node", "--chain", "local", "--validator", "--base-path", "/b"], None),
    (validator_argv("--base-path", "/a", "-d", "/b"), "more than once"),
    (validator_argv("--base-path", "/a", "--keystore-path", "/k", "--keystore-path=/j"), "more than once"),
])
def test_an_unresolvable_keystore_refuses(host, argv, reason):
    host.process(1, argv)
    with pytest.raises(sk.SeatKeyError) as e:
        sk.probe(host.proc, SUFFIX if argv[2] != "local" else "local", ["aura"])
    if reason:
        assert reason in str(e.value)


def test_a_spec_without_an_id_refuses(host):
    host.file(f"/srv/materios/{SUFFIX}", json.dumps({"name": "x"}))
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    with pytest.raises(sk.SeatKeyError, match="no id"):
        host.probe("aura")


def test_a_missing_keystore_directory_refuses(host):
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    with pytest.raises(sk.SeatKeyError, match="no keystore"):
        host.probe("aura")


@pytest.mark.parametrize("count", [0, 2])
def test_zero_or_several_matching_validators_refuse(host, count):
    for pid in range(1, count + 1):
        host.process(pid, validator_argv("--base-path", "/srv/materios/data"))
    with pytest.raises(sk.SeatKeyError, match=f"{count} validator"):
        host.probe("aura")


def test_a_node_run_by_another_user_refuses(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--base-path", "/srv/materios/data"), uid=os.geteuid() + 1)
    with pytest.raises(sk.SeatKeyError, match="run the probe as"):
        host.probe("aura")


def run_over_stdin(host: Host, *args: str) -> subprocess.CompletedProcess:
    # The ceremony ships this file to each host as `ssh host python3 - ARGS` with the source on stdin.
    return subprocess.run([sys.executable, "-", "--proc", str(host.proc), "--chain-suffix", SUFFIX, *args],
                          input=(HERE / "seat_keys.py").read_text(), capture_output=True, text=True,
                          check=False, cwd="/")


def test_cli_over_stdin_prints_the_probe_as_json(host):
    host.key(KEYSTORE, "aura", AURA_A)
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    r = run_over_stdin(host, "aura", "gran")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == {"pid": 1, "keystore": KEYSTORE,
                                    "held": {"aura": ["0x" + AURA_A], "gran": []},
                                    "unreadable": {"aura": [], "gran": []}}


def test_cli_refusal_exits_2_with_the_reason(host):
    host.process(1, validator_argv())
    r = run_over_stdin(host, "aura")
    assert r.returncode == 2
    assert r.stdout == ""
    assert "no --base-path" in r.stderr


def test_cli_refuses_a_key_type_that_is_not_four_ascii_bytes(host):
    host.process(1, validator_argv("--base-path", "/srv/materios/data"))
    r = run_over_stdin(host, "aur")
    assert r.returncode == 2
    assert "key type" in r.stderr
