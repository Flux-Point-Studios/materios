import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import validator_host

lp = validator_host.lp

TOOL = Path(__file__).with_name("validator_host.py")
# sp-core's `seeded_pair_should_work` seed and the public key each scheme derives from it.
SEED = b"12345678901234567890123456789012"
AURA = "741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"
GRANDPA = "2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee"
CROSS_CHAIN = "035676109c54b9a16d271abeb4954316a40a32bcce023ac14c8e26e958aa68fba9"
# RFC 8032 test 1: the libp2p identity an ed25519 node key gives.
NODE_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PEER_ID = "12D3KooWQK1wnefoLrcVHbbnf5tLzbopUd3K3bFAoJpA7YJgL5pV"
# The two session keys as the Cardano setup kit's candidates.py prints their SS58 addresses.
AURA_SS58 = "5Egwjr3bfKhoPMQHxX3HzgJCHYo8bHNxdXiNHGLaXhjhuoqC"
GRANDPA_SS58 = "5D93otKkwohrn4D7e21unUAJTkEfMRrvS8tRZykBBVkGwR8g"
ROW = f"{CROSS_CHAIN}:{AURA}:{GRANDPA}"
# A proof val-1 made from SEED, kept as written: the message its three keys signed is
# materios-validator-host-pop-v1, the name and the row, one a line.
FIXED_PROOF = {
    "name": "val-1", "aura": "0x" + AURA, "grandpa": "0x" + GRANDPA, "cross_chain": "0x" + CROSS_CHAIN,
    "signatures": {
        "aura": "0x84050c5f2ef05dfdb5d7c30663f7c24e0133589be2d4ec599affc79972764d669ebfa1eedb8922b94dbd0bd41be54afa"
                "433e732210923ff664fd33de6cca2881",
        "grandpa": "0xb9932d316d98916f8fa37247949d5b18c4b975f3ff09234b1140cadb04b3d933f0d5850485b536beab9a304d80324b"
                   "47c8661a417d77debd487ccc20d4977207",
        "cross_chain": "0x3044022052e37feac6dc56ddf29e6cbda37a961b74e78ffbaf0999e4e1c36a95b0bc1540022016e332a0918bda"
                       "96d86780aa43a05ad449fcef373ebf718191da51d1fc6499fb"}}


def run(*args, stdin=None):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True, input=stdin)


def ok(*args):
    done = run(*args)
    assert done.returncode == 0, done.stderr
    return done.stdout


def refused(*args):
    done = run(*args)
    assert done.returncode == 1, (done.returncode, done.stdout, done.stderr)
    assert done.stdout == "" and "Traceback" not in done.stderr
    assert done.stderr.startswith("validator-host: ") and done.stderr.count("\n") == 1
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
        f"candidates row: {ROW}",
    ]


def test_keygen_writes_private_files_and_prints_no_secret(tmp_path):
    keystore, node_key = tmp_path / "base" / "keystore", tmp_path / "base" / "node-key"
    done = run("keygen", "--keystore", keystore, "--node-key", node_key)
    assert done.returncode == 0 and done.stderr == ""
    assert done.stdout == ok("show", "--keystore", keystore, "--node-key", node_key)
    entries = sorted(keystore.iterdir())
    assert [e.name[:8] for e in entries] == [t.encode().hex() for t in ("aura", "crch", "gran")]
    secrets = [json.loads(e.read_text()) for e in entries] + ["0x" + node_key.read_text()]
    assert len(set(secrets)) == 4
    for secret in secrets:
        assert len(secret) == 66 and secret[2:] not in done.stdout
    for path in (*entries, node_key):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(keystore.stat().st_mode) == 0o700


def test_every_secret_comes_from_the_systems_generator_32_bytes_each(tmp_path, monkeypatch):
    asked = []

    def token_bytes(n):
        asked.append(n)
        return bytes([len(asked)]) * 32
    monkeypatch.setattr(validator_host.secrets, "token_bytes", token_bytes)
    keystore, node_key = tmp_path / "keystore", tmp_path / "node-key"
    validator_host.keygen(keystore, node_key)
    assert asked == [32, 32, 32, 32]
    held = sorted([json.loads(e.read_text())[2:] for e in keystore.iterdir()] + [node_key.read_text()])
    assert held == [(bytes([i]) * 32).hex() for i in (1, 2, 3, 4)]


def test_keygen_tightens_a_keystore_directory_others_could_enter(tmp_path):
    keystore = tmp_path / "keystore"
    keystore.mkdir()
    keystore.chmod(0o777)
    ok("keygen", "--keystore", keystore, "--node-key", tmp_path / "node-key")
    assert stat.S_IMODE(keystore.stat().st_mode) == 0o700


def test_keygen_never_writes_over_a_key(tmp_path):
    keystore, node_key = seeded(tmp_path)
    before = {p: p.read_text() for p in (*keystore.iterdir(), node_key)}
    assert "already holds" in refused("keygen", "--keystore", keystore, "--node-key", tmp_path / "other")
    assert "already exists" in refused("keygen", "--keystore", tmp_path / "fresh", "--node-key", node_key)
    assert not (tmp_path / "other").exists() and not (tmp_path / "fresh").exists()
    assert before == {p: p.read_text() for p in before}


def test_keygen_never_writes_through_a_link(tmp_path):
    target, node_key = tmp_path / "elsewhere", tmp_path / "node-key"
    node_key.symlink_to(target)
    assert "node-key" in refused("keygen", "--keystore", tmp_path / "keystore", "--node-key", node_key)
    assert not target.exists() and not list((tmp_path / "keystore").glob("*"))


@pytest.mark.parametrize("blocked", ["node-key", "keystore"])
def test_keygen_leaves_nothing_behind_when_a_path_cannot_be_written(tmp_path, blocked):
    (tmp_path / "file").write_text("")
    paths = {"keystore": tmp_path / "keystore", "node-key": tmp_path / "node-key"}
    good = dict(paths)
    paths[blocked] = tmp_path / "file" / blocked
    refused("keygen", "--keystore", paths["keystore"], "--node-key", paths["node-key"])
    assert not good["node-key"].exists() and not list(good["keystore"].glob("*"))
    ok("keygen", "--keystore", good["keystore"], "--node-key", good["node-key"])


@pytest.mark.parametrize("command", ["keygen", "show"])
def test_a_keystore_path_that_is_a_file_is_refused_in_one_line(tmp_path, command):
    (tmp_path / "file").write_text("")
    refused(command, "--keystore", tmp_path / "file", "--node-key", tmp_path / "node-key")
    assert not (tmp_path / "node-key").exists()


def test_keygen_makes_fresh_secrets_each_time(tmp_path):
    def secrets_of(name):
        keystore, node_key = tmp_path / name / "keystore", tmp_path / name / "node-key"
        ok("keygen", "--keystore", keystore, "--node-key", node_key)
        return {e.read_text() for e in keystore.iterdir()} | {node_key.read_text()}
    first, second = secrets_of("a"), secrets_of("b")
    assert len(first) == len(second) == 4 and not first & second


def test_show_reads_a_node_key_of_raw_bytes_as_no_key_and_shows_none_of_it(tmp_path):
    keystore, node_key = seeded(tmp_path)
    raw = bytes(range(0x80, 0xa0))
    node_key.write_bytes(raw)
    said = refused("show", "--keystore", keystore, "--node-key", node_key).replace(str(node_key), "")
    assert "in hex" in said
    for byte in raw:
        assert f"{byte:02x}" not in said.lower() and str(byte) not in said and chr(byte) not in said


def test_keygen_makes_every_directory_private_whatever_the_umask(tmp_path):
    base = tmp_path / "base"
    keystore, node_key = base / "chains" / "materios_mainnet" / "keystore", base / "keys" / "node-key"
    done = subprocess.run([sys.executable, str(TOOL), "keygen", "--keystore", keystore, "--node-key", node_key],
                          capture_output=True, text=True, preexec_fn=lambda: os.umask(0))
    assert done.returncode == 0, done.stderr
    made = [base, base / "chains", base / "chains" / "materios_mainnet", keystore, base / "keys"]
    assert [stat.S_IMODE(d.stat().st_mode) for d in made] == [0o700] * 5
    assert {stat.S_IMODE(f.stat().st_mode) for f in (*keystore.iterdir(), node_key)} == {0o600}


@pytest.mark.parametrize("inside", ["node-key", "sub/node-key"])
def test_keygen_refuses_a_node_key_inside_the_keystore_before_any_write(tmp_path, inside):
    keystore = tmp_path / "keystore"
    assert "inside the keystore" in refused("keygen", "--keystore", keystore, "--node-key", keystore / inside)
    assert not keystore.exists()
    ok("keygen", "--keystore", keystore, "--node-key", tmp_path / "node-key")


def test_show_refuses_a_seed_that_is_no_secret_of_its_scheme(tmp_path):
    keystore, node_key = seeded(tmp_path)
    (keystore / ("crch".encode().hex() + CROSS_CHAIN)).write_text(json.dumps("0x" + "00" * 32))
    assert "crch entry" in refused("show", "--keystore", keystore, "--node-key", node_key)


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


def manifest(tmp_path, name="val-1", **keys):
    declared = {"aura": "0x" + AURA, "grandpa": "0x" + GRANDPA, "cross_chain": "0x" + CROSS_CHAIN, **keys}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"nodes": [{"name": name, "authority": True, **declared}]}))
    return path


def verify(tmp_path, doc, name="val-1", **keys):
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(doc))
    return run("verify", path, "--launch", manifest(tmp_path, **keys), "--name", name)


def refuses(done, reason):
    assert done.returncode == 1 and done.stdout == "" and "Traceback" not in done.stderr
    assert reason in done.stderr, done.stderr


def other_proof(tmp_path, name="val-1"):
    """A proof by a second, freshly made validator."""
    keystore = tmp_path / "second" / "keystore"
    if not keystore.exists():
        ok("keygen", "--keystore", keystore, "--node-key", tmp_path / "second" / "node-key")
    return json.loads(ok("prove", "--keystore", keystore, "--name", name))


PASS = ["PASS: val-1 holds the three keys the manifest declares for it", f"candidates row: {ROW}"]


def test_the_fixed_proof_verifies_against_the_manifests_keys(tmp_path):
    done = verify(tmp_path, FIXED_PROOF)
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines() == PASS


def test_a_fresh_proof_verifies_and_reads_the_manifests_keys_as_ss58_too(tmp_path):
    keystore, _ = seeded(tmp_path)
    doc = json.loads(ok("prove", "--keystore", keystore, "--name", "val-1"))
    assert {k: doc[k] for k in ("name", "aura", "grandpa", "cross_chain")} == {
        k: FIXED_PROOF[k] for k in ("name", "aura", "grandpa", "cross_chain")}
    assert doc["signatures"]["grandpa"] == FIXED_PROOF["signatures"]["grandpa"]
    done = verify(tmp_path, doc, aura=AURA_SS58, grandpa=GRANDPA_SS58)
    assert done.returncode == 0 and done.stdout.splitlines() == PASS


@pytest.mark.parametrize("key", ["aura", "grandpa", "cross_chain"])
def test_a_pass_is_about_the_manifests_row_not_the_proofs(tmp_path, key):
    theirs = other_proof(tmp_path)
    refuses(verify(tmp_path, theirs), "is not the one")
    refuses(verify(tmp_path, FIXED_PROOF, **{key: theirs[key]}), f"its {key} key is not the one")


def test_a_manifest_key_with_a_wrong_ss58_checksum_is_no_key(tmp_path):
    swapped = AURA_SS58[:-1] + ("D" if AURA_SS58[-1] != "D" else "E")
    refuses(verify(tmp_path, FIXED_PROOF, aura=swapped), "aura key of val-1 is no 32-byte public key")
    refuses(verify(tmp_path, FIXED_PROOF, cross_chain=AURA_SS58), "cross_chain key of val-1 is no 33-byte public key")


def test_two_authorities_under_one_name_are_refused(tmp_path):
    path = manifest(tmp_path)
    doc = json.loads(path.read_text())
    path.write_text(json.dumps({"nodes": doc["nodes"] * 2}))
    (tmp_path / "proof.json").write_text(json.dumps(FIXED_PROOF))
    refuses(run("verify", tmp_path / "proof.json", "--launch", path, "--name", "val-1"), "2 authorities named val-1")


P = 2**255 - 19
SECP = 2**256 - 2**32 - 977
# Keys nobody holds, or everybody does. sr25519: the ristretto identity, whose signature of R and s zero verifies
# for any message; an s that is odd; an s that is not below the field prime; an s of no point (RFC 9496, A.3).
NO_AURA = {
    "identity": bytes(32),
    "negative": (1).to_bytes(32, "little"),
    "not below p": P.to_bytes(32, "little"),
    "all ones": bytes([255]) * 32,
    "no point": bytes.fromhex("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"),
}
# ed25519: every encoding the node's verifier reads as a key of small order, a y that is not below p, and one
# that is no key of the prime-order group.
NO_GRANDPA = {
    **{f"small order {key.hex()[:8]}…{key.hex()[-2:]}": key for key in sorted(lp.ED25519_SMALL_ORDER)},
    "y = p + 3": (P + 3).to_bytes(32, "little"),
    "y = 2": (2).to_bytes(32, "little"),
}
# secp256k1: 33 bytes that are no compressed point.
NO_CROSS_CHAIN = {
    "prefix 00 (infinity)": bytes(33),
    "prefix 04": b"\x04" + bytes.fromhex(CROSS_CHAIN)[1:],
    "prefix 01": b"\x01" + bytes.fromhex(CROSS_CHAIN)[1:],
    "x = 5, on no point": b"\x02" + (5).to_bytes(32, "big"),
    "x = 0, on no point": b"\x02" + bytes(32),
    "x = p": b"\x02" + SECP.to_bytes(32, "big"),
    "x = p + 1": b"\x03" + (SECP + 1).to_bytes(32, "big"),
}
UNUSABLE = [(key, label, value) for key, table in (("aura", NO_AURA), ("grandpa", NO_GRANDPA),
                                                   ("cross_chain", NO_CROSS_CHAIN)) for label, value in table.items()]


def test_the_small_order_table_is_the_fourteen_encodings():
    assert len(lp.ED25519_SMALL_ORDER) == 14


@pytest.mark.parametrize("key, label, value", UNUSABLE, ids=[f"{k}: {label}" for k, label, _ in UNUSABLE])
def test_verify_refuses_a_manifest_key_no_secret_stands_behind(tmp_path, key, label, value):
    """Whatever the proof holds: the same bytes as its key, and for the keys that verify without a secret the
    signature that does."""
    doc = json.loads(json.dumps(FIXED_PROOF))
    doc[key] = "0x" + value.hex()
    doc["signatures"][key] = "0x" + (bytes(63) + b"\x80" if key == "aura" else bytes(64)).hex()
    refuses(verify(tmp_path, doc, **{key: "0x" + value.hex()}), f"{key} key of val-1")


def test_the_identity_and_a_small_order_key_do_verify_without_a_secret():
    """Why the refusal cannot be left to the signature check."""
    assert validator_host.signed("aura", bytes(32), bytes(63) + b"\x80", b"any message")


def test_a_proof_is_for_the_validator_asked_about(tmp_path):
    refuses(verify(tmp_path, FIXED_PROOF, name="val-2"), "declares no authority named val-2")
    path = tmp_path / "proof.json"
    path.write_text(json.dumps(FIXED_PROOF))
    done = run("verify", path, "--launch", manifest(tmp_path, name="val-2"), "--name", "val-2")
    refuses(done, "names another validator")


@pytest.mark.parametrize("key", ["aura", "grandpa", "cross_chain"])
def test_a_proof_needs_each_keys_own_signature(tmp_path, key):
    doc = json.loads(json.dumps(FIXED_PROOF))
    doc["signatures"][key] = other_proof(tmp_path)["signatures"][key]
    refuses(verify(tmp_path, doc), f"{key} signature does not verify")


FORGED = "val-1\ncandidates row: " + "02" + "11" * 32 + ":" + "22" * 32 + ":" + "33" * 32 + "\x1b[8m"


@pytest.mark.parametrize("name", [FORGED, "val 1", "", "v" * 65, "val-1\n", "v\u00e4l"])
def test_no_command_takes_or_prints_a_name_that_is_not_plain(tmp_path, name):
    keystore, _ = seeded(tmp_path)
    for done in (run("prove", "--keystore", keystore, "--name", name),
                 run("verify", tmp_path / "none", "--launch", manifest(tmp_path), "--name", name),
                 run("unit", "--launch", launch(tmp_path), "--name", name, "--env-file", "/etc/materios/v.env")):
        refuses(done, "is no validator name")
        assert done.stderr.isascii() and "\x1b" not in done.stderr and done.stderr.count("\n") == 1


def test_verify_prints_nothing_a_proof_brings(tmp_path):
    """A proof its maker signed under a name that draws a second PASS and a forged row on the screen."""
    mine = other_proof(tmp_path)
    mine["name"] = FORGED
    done = verify(tmp_path, mine, **{k: mine[k] for k in ("aura", "grandpa", "cross_chain")})
    refuses(done, "names another validator")
    assert "11" * 32 not in done.stderr and "\x1b" not in done.stderr and done.stderr.count("\n") == 1


DEEP = "[" * 100000 + "]" * 100000


@pytest.mark.parametrize("doc", ["[]", "{}", '{"name": 5}', "not json", json.dumps({**FIXED_PROOF, "aura": "0xzz"}),
                                 json.dumps({**FIXED_PROOF, "signatures": []}), DEEP],
                         ids=["list", "empty", "number name", "not json", "bad hex", "no signatures", "deep"])
def test_verify_refuses_a_file_that_is_no_proof(tmp_path, doc):
    path = tmp_path / "proof.json"
    path.write_text(doc)
    refuses(run("verify", path, "--launch", manifest(tmp_path), "--name", "val-1"), "")


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


NODE = "/usr/local/bin/materios-node"
BASE_ARGV = [NODE, "--validator", "--chain", "/srv/materios/spec/mainnet-raw.json", "--rpc-methods", "safe"]


@pytest.mark.parametrize("changes, name, reason", [
    ({}, "val-9", "no authority named val-9"),
    ({}, "rpc-1", "no authority named rpc-1"),
    ({"argv": ["materios-node", *BASE_ARGV[1:]]}, "val-1", "argv[0] of val-1 must be the absolute path"),
    ({"argv": [*BASE_ARGV, "--name", "50%"]}, "val-1", "systemd would rewrite"),
    ({"argv": [*BASE_ARGV, "--name", "a$b"]}, "val-1", "systemd would rewrite"),
    ({"argv": [*BASE_ARGV, "--name", 'a"b']}, "val-1", "systemd would rewrite"),
    ({"argv": [*BASE_ARGV, "--name", "a\nb"]}, "val-1", "systemd would rewrite"),
    ({"env": {"MAIN_CHAIN_FOLLOWER": "db\\sync"}}, "val-1", "systemd would rewrite"),
    ({"env": {"BAD NAME": "1"}}, "val-1", "is no environment name"),
    ({"argv": []}, "val-1", "argv"),
    ({"argv": "materios-node --validator"}, "val-1", "argv"),
    ({"argv": [NODE, 7]}, "val-1", "argv"),
    ({"argv": None}, "val-1", "argv"),
    ({"env": None}, "val-1", "env"),
    ({"env": ["A=1"]}, "val-1", "env"),
    ({"env": {"A": 1}}, "val-1", "env"),
    *[({"argv": [*BASE_ARGV, *flag]}, "val-1", reason) for reason, flags in {
        "loads keys every developer holds": (["--dev"], ["--alice"], ["--bob"], ["--charlie"], ["--dave"], ["--eve"],
                                             ["--ferdie"], ["--one"], ["--two"]),
        "beyond loopback": (["--unsafe-rpc-external"], ["--rpc-external"],
                            ["--experimental-rpc-endpoint", "listen-addr=0.0.0.0:9944,methods=safe"],
                            ["--experimental-rpc-endpoint=listen-addr=0.0.0.0:9944,methods=safe"],
                            ["--experimental-rpc-endpoint", "listen-addr=[::]:9944,methods=safe"],
                            ["--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9955,methods=safe",
                             "listen-addr=10.0.0.5:9956,methods=safe"]),
        "methods other than safe": (["--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9955,methods=unsafe"],
                                    ["--experimental-rpc-endpoint=listen-addr=127.0.0.1:9955,methods=Unsafe"],
                                    ["--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9955"],
                                    ["--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9955,methods=auto"]),
        "has no listen-addr": (["--experimental-rpc-endpoint", "methods=safe"],),
        "a secret in its argv": (["--password", "hunter2"], ["--password=hunter2"], ["--node-key", "00" * 32],
                                 ["--node-key=" + "00" * 32]),
    }.items() for flag in flags],
    *[({"argv": argv}, "val-1", reason) for argv, reason in [
        ([NODE, "--validator", "--chain", "/srv/materios/spec/mainnet-raw.json", "--rpc-methods", "unsafe"],
         "methods other than safe"),
        ([NODE, "--validator", "--chain", "/srv/materios/spec/mainnet-raw.json", "--rpc-methods=Unsafe"],
         "methods other than safe"),
        ([NODE, "--validator", "--chain", "/srv/materios/spec/mainnet-raw.json"], "methods other than safe"),
        ([NODE, "--chain", "/srv/materios/spec/mainnet-raw.json", "--rpc-methods", "safe"], "without --validator"),
        ([NODE, "--validator", "--rpc-methods", "safe"], "--chain"),
        ([NODE, "--validator", "--chain", "dev", "--rpc-methods", "safe"], "--chain"),
        ([NODE, "--validator", "--chain=local", "--rpc-methods", "safe"], "--chain"),
        ([NODE, "--validator", "--chain", "spec/mainnet-raw.json", "--rpc-methods", "safe"], "--chain"),
        ([NODE, "--validator", "--chain", "/a.json", "--chain", "/b.json", "--rpc-methods", "safe"], "--chain"),
    ]],
    *[({"env": {name: "/tmp/x.so"}}, "val-1", "loader")
      for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "ld_preload")],
])
def test_unit_refuses_what_it_cannot_write_exactly_or_must_not_start(tmp_path, changes, name, reason):
    assert reason in refused("unit", "--launch", launch(tmp_path, **changes), "--name", name,
                             "--env-file", "/etc/materios/validator.env")


@pytest.mark.parametrize("missing", ["argv", "env"])
def test_unit_refuses_an_entry_without_its_argv_or_env(tmp_path, missing):
    path = launch(tmp_path)
    doc = json.loads(path.read_text())
    del doc["nodes"][1][missing]
    path.write_text(json.dumps(doc))
    assert missing in refused("unit", "--launch", path, "--name", "val-1", "--env-file", "/etc/materios/v.env")


@pytest.mark.parametrize("doc", ["[]", '{"nodes": 5}', '{"nodes": [5]}', "not json", DEEP],
                         ids=["list", "number", "number node", "not json", "deep"])
def test_unit_and_verify_refuse_a_file_that_is_no_manifest(tmp_path, doc):
    path = tmp_path / "launch.json"
    path.write_text(doc)
    refused("unit", "--launch", path, "--name", "val-1", "--env-file", "/etc/materios/v.env")
    (tmp_path / "proof.json").write_text(json.dumps(FIXED_PROOF))
    refused("verify", tmp_path / "proof.json", "--launch", path, "--name", "val-1")


def test_a_deeply_nested_keystore_entry_is_refused_in_one_line(tmp_path):
    keystore, node_key = seeded(tmp_path)
    (keystore / ("aura".encode().hex() + AURA)).write_text(DEEP)
    refused("show", "--keystore", keystore, "--node-key", node_key)


@pytest.mark.parametrize("user", ["mat%erios", "materios\nExecStartPre=/bin/x", "Materios", "", "a b"])
def test_unit_refuses_a_user_that_is_no_user_name(tmp_path, user):
    assert "is no user name" in refused("unit", "--launch", launch(tmp_path), "--name", "val-1", "--user", user,
                                        "--env-file", "/etc/materios/validator.env")


def test_unit_takes_a_loopback_endpoint_with_safe_methods(tmp_path):
    argv = [*BASE_ARGV, "--experimental-rpc-endpoint", "listen-addr=127.0.0.1:9955,methods=safe"]
    assert '"listen-addr=127.0.0.1:9955,methods=safe"' in ok(
        "unit", "--launch", launch(tmp_path, argv=argv), "--name", "val-1", "--env-file", "/etc/materios/v.env")


def test_unit_refuses_a_relative_env_file(tmp_path):
    assert "absolute path" in refused("unit", "--launch", launch(tmp_path), "--name", "val-1",
                                      "--env-file", "validator.env")


def test_a_bad_command_line_exits_2():
    for args in (["keygen"], []):
        done = run(*args)
        assert done.returncode == 2 and "usage: validator_host.py" in done.stderr
