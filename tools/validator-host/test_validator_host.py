import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).with_name("validator_host.py")
# sp-core's `seeded_pair_should_work` seed and the public key each scheme derives from it.
SEED = b"12345678901234567890123456789012"
AURA = "741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"
GRANDPA = "2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee"
CROSS_CHAIN = "035676109c54b9a16d271abeb4954316a40a32bcce023ac14c8e26e958aa68fba9"
# RFC 8032 test 1: the libp2p identity an ed25519 node key gives.
NODE_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PEER_ID = "12D3KooWQK1wnefoLrcVHbbnf5tLzbopUd3K3bFAoJpA7YJgL5pV"


def run(*args, stdin=None):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True, input=stdin)


def ok(*args):
    done = run(*args)
    assert done.returncode == 0, done.stderr
    return done.stdout


def refused(*args):
    done = run(*args)
    assert done.returncode == 1, (done.returncode, done.stdout, done.stderr)
    assert done.stdout == ""
    return done.stderr


def seeded(tmp_path):
    """A keystore and node key holding the known seeds, as keygen lays them out."""
    keystore = tmp_path / "keystore"
    keystore.mkdir()
    for key_type, public in (("aura", AURA), ("gran", GRANDPA), ("crch", CROSS_CHAIN)):
        (keystore / (key_type.encode().hex() + public)).write_text(json.dumps("0x" + SEED.hex()))
    node_key = tmp_path / "node-key"
    node_key.write_text(NODE_SEED)
    return keystore, node_key


def test_show_derives_each_scheme_as_the_node_does(tmp_path):
    keystore, node_key = seeded(tmp_path)
    assert ok("show", "--keystore", keystore, "--node-key", node_key).splitlines() == [
        f"aura key: 0x{AURA}",
        f"grandpa key: 0x{GRANDPA}",
        f"partner-chain key: 0x{CROSS_CHAIN}",
        f"peer id: {PEER_ID}",
        f"candidates row: {CROSS_CHAIN}:{AURA}:{GRANDPA}",
    ]


def test_keygen_writes_private_files_and_prints_no_secret(tmp_path):
    keystore, node_key = tmp_path / "base" / "keystore", tmp_path / "etc" / "node-key"
    out = ok("keygen", "--keystore", keystore, "--node-key", node_key)
    assert out == ok("show", "--keystore", keystore, "--node-key", node_key)
    entries = sorted(keystore.iterdir())
    assert [e.name[:8] for e in entries] == [t.encode().hex() for t in ("aura", "crch", "gran")]
    secrets = [json.loads(e.read_text()) for e in entries] + ["0x" + node_key.read_text()]
    assert len(set(secrets)) == 4
    for secret in secrets:
        assert len(secret) == 66 and secret[2:] not in out
    for path in (*entries, node_key):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(keystore.stat().st_mode) == 0o700


def test_keygen_makes_fresh_secrets_each_time(tmp_path):
    def secrets_of(name):
        keystore, node_key = tmp_path / name / "keystore", tmp_path / name / "node-key"
        ok("keygen", "--keystore", keystore, "--node-key", node_key)
        return {e.read_text() for e in keystore.iterdir()} | {node_key.read_text()}
    first, second = secrets_of("a"), secrets_of("b")
    assert len(first) == len(second) == 4 and not first & second


def test_keygen_never_writes_over_a_key(tmp_path):
    keystore, node_key = seeded(tmp_path)
    before = {p: p.read_text() for p in (*keystore.iterdir(), node_key)}
    assert "already holds" in refused("keygen", "--keystore", keystore, "--node-key", tmp_path / "other")
    assert "already exists" in refused("keygen", "--keystore", tmp_path / "fresh", "--node-key", node_key)
    assert not (tmp_path / "other").exists() and not (tmp_path / "fresh").exists()
    assert before == {p: p.read_text() for p in before}


@pytest.mark.parametrize("damage, reason", [
    (lambda k: (k / ("aura".encode().hex() + AURA)).rename(k / ("aura".encode().hex() + GRANDPA)), "does not derive"),
    (lambda k: (k / ("gran".encode().hex() + GRANDPA)).write_text('"bottom drive obey lake"'), "32-byte seed"),
    (lambda k: (k / ("crch".encode().hex() + CROSS_CHAIN)).unlink(), "exactly one"),
    (lambda k: (k / ("aura".encode().hex() + "00" * 32)).write_text(json.dumps("0x" + "11" * 32)), "exactly one"),
    (lambda k: (k / "notes.txt").write_text("x"), "is no key entry"),
])
def test_show_refuses_a_keystore_the_row_would_misstate(tmp_path, damage, reason):
    keystore, node_key = seeded(tmp_path)
    damage(keystore)
    assert reason in refused("show", "--keystore", keystore, "--node-key", node_key)


def proof(tmp_path):
    keystore, _ = seeded(tmp_path)
    return json.loads(ok("prove", "--keystore", keystore, "--name", "val-1"))


def verify(tmp_path, doc):
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(doc))
    return run("verify", path)


def test_a_proof_verifies_and_names_the_row(tmp_path):
    doc = proof(tmp_path)
    assert set(doc) == {"name", "aura", "grandpa", "cross_chain", "signatures"}
    done = verify(tmp_path, doc)
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == ["PASS: val-1 signed with all three keys",
                                        f"candidates row: {CROSS_CHAIN}:{AURA}:{GRANDPA}"]


def other_keys(tmp_path):
    """The three public keys of a second, freshly made validator."""
    keystore = tmp_path / "second" / "keystore"
    ok("keygen", "--keystore", keystore, "--node-key", tmp_path / "second" / "node-key")
    return json.loads(ok("prove", "--keystore", keystore, "--name", "val-1"))


@pytest.mark.parametrize("field", ["name", "aura", "grandpa", "cross_chain"])
def test_a_proof_binds_the_name_and_every_key(tmp_path, field):
    doc = proof(tmp_path)
    doc[field] = "val-2" if field == "name" else other_keys(tmp_path)[field]
    done = verify(tmp_path, doc)
    assert done.returncode == 1 and done.stdout == "" and "does not verify" in done.stderr


@pytest.mark.parametrize("key", ["aura", "grandpa", "cross_chain"])
def test_a_proof_needs_each_keys_own_signature(tmp_path, key):
    doc = proof(tmp_path)
    doc["signatures"][key] = other_keys(tmp_path)["signatures"][key]
    done = verify(tmp_path, doc)
    assert done.returncode == 1 and f"{key} signature does not verify" in done.stderr


def launch(tmp_path, **changes):
    node = {"name": "val-1", "authority": True,
            "argv": ["/usr/local/bin/materios-node", "--validator", "--chain", "/srv/materios/spec/mainnet-raw.json",
                     "--name", "val-1", "--rpc-methods", "safe"],
            "env": {"MAIN_CHAIN_FOLLOWER": "db-sync", "BLOCK_STABILITY_MARGIN": "0",
                    "DB_SYNC_POSTGRES_CONNECTION_STRING": "db-sync.internal:5432/cexplorer"}}
    node.update(changes)
    path = tmp_path / "launch.json"
    path.write_text(json.dumps({"nodes": [{"name": "rpc-1", "authority": False, "argv": ["x"], "env": {}}, node]}))
    return path


EXPECTED_UNIT = """\
[Unit]
Description=Materios mainnet validator val-1
Wants=network-online.target
After=network-online.target

[Service]
User=materios
ExecStart="/usr/local/bin/materios-node" "--validator" "--chain" "/srv/materios/spec/mainnet-raw.json" \
"--name" "val-1" "--rpc-methods" "safe"
Environment="BLOCK_STABILITY_MARGIN=0"
Environment="MAIN_CHAIN_FOLLOWER=db-sync"
EnvironmentFile=/etc/materios/validator.env
Restart=on-failure
RestartSec=120
LimitNOFILE=65536
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
"""


def test_unit_runs_the_manifest_argv_and_env_word_for_word(tmp_path):
    out = ok("unit", "--launch", launch(tmp_path), "--name", "val-1", "--user", "materios",
             "--env-file", "/etc/materios/validator.env")
    assert out == EXPECTED_UNIT


def test_unit_for_a_user_manager_names_no_user(tmp_path):
    out = ok("unit", "--launch", launch(tmp_path), "--name", "val-1", "--env-file", "/etc/materios/validator.env")
    assert "User=" not in out and "WantedBy=default.target" in out


@pytest.mark.parametrize("changes, name, reason", [
    ({}, "val-9", "no authority named val-9"),
    ({}, "rpc-1", "no authority named rpc-1"),
    ({"argv": ["materios-node", "--validator"]}, "val-1", "absolute path"),
    ({"argv": ["/usr/local/bin/materios-node", "--name", "50%"]}, "val-1", "systemd would rewrite"),
    ({"argv": ["/usr/local/bin/materios-node", "--name", "a$b"]}, "val-1", "systemd would rewrite"),
    ({"argv": ["/usr/local/bin/materios-node", "--name", 'a"b']}, "val-1", "systemd would rewrite"),
    ({"argv": ["/usr/local/bin/materios-node", "--name", "a\nb"]}, "val-1", "systemd would rewrite"),
    ({"env": {"MAIN_CHAIN_FOLLOWER": "db\\sync"}}, "val-1", "systemd would rewrite"),
    ({"env": {"BAD NAME": "1"}}, "val-1", "is no environment name"),
])
def test_unit_refuses_what_it_cannot_write_exactly(tmp_path, changes, name, reason):
    assert reason in refused("unit", "--launch", launch(tmp_path, **changes), "--name", name,
                             "--env-file", "/etc/materios/validator.env")


def test_unit_refuses_a_relative_env_file(tmp_path):
    assert "absolute path" in refused("unit", "--launch", launch(tmp_path), "--name", "val-1",
                                      "--env-file", "validator.env")


def test_a_bad_command_line_exits_2():
    for args in (["keygen"], []):
        done = run(*args)
        assert done.returncode == 2 and "usage: validator_host.py" in done.stderr
