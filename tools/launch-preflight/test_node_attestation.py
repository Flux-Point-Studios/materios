"""Rule 8 against the real materios-node binary, which MATERIOS_NODE names; CI builds it from this tree. Every node
run is offline, on a base path of its own, and a node started to serve its genesis listens on loopback only, with no
peers. The spec is a fresh `build-spec --chain preprod --raw` from that binary."""
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

import launch_preflight as lp
import test_launch_preflight as base

# The fixtures the CLI tests take by name.
clean, endpoint, kupo, metadata_v14, preprod_path = (
    base.clean, base.endpoint, base.kupo, base.metadata_v14, base.preprod_path)


@pytest.fixture(scope="module")
def node() -> Path:
    path = os.environ.get("MATERIOS_NODE")
    assert path, "set MATERIOS_NODE to a materios-node binary: these tests run the real node"
    return Path(path).resolve()


@pytest.fixture(scope="module")
def pin(node) -> str:
    return "0x" + hashlib.sha256(node.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def preprod(node, tmp_path_factory) -> Path:
    """The preprod chain spec the binary builds in, raw, as the fixture recipe builds it."""
    tmp = tmp_path_factory.mktemp("build-spec")
    built = subprocess.run([str(node), "build-spec", "--chain", "preprod", "--raw", "--disable-default-bootnode",
                            "--base-path", str(tmp / "base")], env={}, stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=lp.NODE_TIMEOUT, check=True)
    path = tmp / "preprod-raw.json"
    path.write_bytes(built.stdout)
    return path


# The launch command of an authority like the ones preprod runs, with an option from every group export-blocks
# is given and a sample of those it is not.
LIVE_LIKE = ["--base-path", "/data/materios", "--validator", "--name", "val0", "--port", "30333", "--rpc-port", "9945",
             "--rpc-cors", "all", "--rpc-methods", "safe", "--rpc-max-connections", "5000", "--pool-limit", "32768",
             "--pool-kbytes", "65536", "--state-pruning", "archive", "--db", "rocksdb", "--db-cache", "256", "-lwarn"]


def attested(tmp_path, node, pin, spec_path: Path, words, chain_spec: bytes | None = None,
             served: str | None = None) -> dict:
    """An authority whose running node serves the genesis the preflight computes, unless the test gives the path of
    what a real node served."""
    argv = ["/usr/local/bin/materios-node", *words]
    copied = tmp_path / "val0.chain.json"
    copied.write_bytes(spec_path.read_bytes() if chain_spec is None else chain_spec)
    served = served or base.served(tmp_path, "val0", lp.spec_genesis_hash(lp.load_spec(str(spec_path))))
    return dict(base.authority(argv, "val0", "val0"), cmdline=base.capture(tmp_path, "val0", argv), exe=str(node),
                exe_sha256=pin, chain_spec=str(copied), served_genesis=served)


def findings(spec_path: Path, entry: dict) -> list[str]:
    return [str(f) for f in lp.check_node_genesis(lp.load_spec(str(spec_path)), base.rpc_launch([entry]))]


def test_the_node_builds_the_genesis_the_preflight_computes_for_a_fresh_preprod_build_spec(tmp_path, node, pin,
                                                                                           preprod):
    entry = attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/mainnet-raw.json", *LIVE_LIKE])
    assert findings(preprod, entry) == []


def test_build_spec_stores_the_last_runtime_upgrade_the_preflight_derives_from_the_code(preprod):
    spec = lp.load_spec(str(preprod))
    assert spec.value("System", "LastRuntimeUpgrade") is not None
    assert lp.check_last_runtime_upgrade(spec) == []


def test_the_node_reads_a_relative_chain_path_as_a_file(tmp_path, node, pin, preprod):
    assert findings(preprod, attested(tmp_path, node, pin, preprod, ["--chain", "mainnet-raw.json"])) == []


# The node's own preprod spec builds the very genesis checked here, and is still refused: an authority that loads
# the chain built into its node does not load the checked spec, its boot nodes, properties or code substitutes.
def test_the_chain_built_into_the_node_as_preprod_is_refused_though_its_genesis_matches(tmp_path, node, pin, preprod):
    genesis = lp.spec_genesis_hash(lp.load_spec(str(preprod))).hex()
    assert findings(preprod, attested(tmp_path, node, pin, preprod, ["--chain=preprod"])) == [
        f"[8 node] authority val0: --chain 'preprod' builds genesis 0x{genesis} with no file of that name here: the "
        "node takes it as a chain built into it, not the checked chain spec"]


# The node panics once it has built these chains' genesis, so it builds no block 0 to export from them.
@pytest.mark.parametrize("name", ["local", "dev", ""])
def test_a_chain_built_into_the_node_that_fails_here_is_an_input_error(tmp_path, node, pin, preprod, name):
    with pytest.raises(lp.InputError, match=re.escape(
            f"authority val0: its node builds no genesis from --chain {name!r} here, and does not report it as a "
            "missing file") + ".*panicked"):
        findings(preprod, attested(tmp_path, node, pin, preprod, ["--chain", name]))


def test_an_authority_that_gives_no_chain_is_refused(tmp_path, node, pin, preprod):
    assert findings(preprod, attested(tmp_path, node, pin, preprod, ["--validator"])) == [
        "[8 node] authority val0 gives no --chain: its node loads the chain built into it as local, not the checked "
        "chain spec"]


def test_a_chain_spec_file_other_than_the_checked_one_is_refused(tmp_path, node, pin, preprod):
    other = json.loads(preprod.read_text())
    other["name"] = "Materios"
    entry = attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/other-raw.json"],
                     chain_spec=json.dumps(other).encode())
    assert findings(preprod, entry)[0].startswith(
        "[8 node] authority val0: its --chain file, as captured, is not the checked chain spec")


# The node refuses a raw genesis with a field it does not know; the preflight reads only its storage.
def test_a_spec_the_preflight_reads_and_the_node_refuses_is_an_input_error(tmp_path, node, pin, preprod):
    doc = json.loads(preprod.read_text())
    doc["genesis"]["raw"]["extra"] = {}
    tampered = tmp_path / "tampered-raw.json"
    tampered.write_text(json.dumps(doc))
    with pytest.raises(lp.InputError, match="authority val0: its node builds no genesis from the checked chain spec: "
                                            ".*unknown field `extra`"):
        findings(tampered, attested(tmp_path, node, pin, tampered, ["--chain", "/srv/materios/mainnet-raw.json"]))


# Any way the preflight reads the spec apart from the node shows as another hash: here it takes the trie layout
# from a state version the runtime does not declare.
def test_a_preflight_that_reads_the_spec_apart_from_the_node_is_refused(tmp_path, node, pin, preprod, monkeypatch):
    genesis = lp.spec_genesis_hash(lp.load_spec(str(preprod))).hex()
    monkeypatch.setattr(lp, "runtime_state_version", lambda wasm: 0)
    computed = lp.spec_genesis_hash(lp.load_spec(str(preprod))).hex()
    assert computed != genesis
    assert findings(preprod, attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/mainnet-raw.json"])) == [
        f"[8 node] authority val0: its node builds genesis 0x{genesis} from the checked chain spec, and the preflight "
        f"computes 0x{computed}: the signed genesis hash and the lock's datum bind the preflight's, not the chain this "
        "authority starts"]


def test_a_binary_other_than_the_pinned_one_is_refused(tmp_path, node, preprod):
    other = "0x" + hashlib.sha256(b"the release binary").hexdigest()
    entry = attested(tmp_path, node, other, preprod, ["--chain", "/srv/materios/mainnet-raw.json"])
    assert findings(preprod, entry)[0].startswith("[8 node] authority val0 runs a node binary whose sha256 is 0x")


# Every option the node's run command takes is one the preflight reads, and export-blocks is given exactly the
# ones it takes itself: the table is the binary's own.
HELP_OPTION = re.compile(r"^\s+(?:(-\w), )?(--[\w-]+)(?: <[^>]+>(?:\.\.\.)?)?$", re.MULTILINE)
# Aliases clap takes and --help does not list.
ALIASES = {"--pruning", "--keep-blocks", "--db", "--no-private-ipv4", "--allow-private-ipv4", "--rpc_no_batch_requests"}
BUILT_IN_OPTIONS = {"-h", "--help", "-V", "--version"}


def help_options(node: Path, *subcommand: str) -> set[str]:
    text = subprocess.run([str(node), *subcommand, "--help"], env={}, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=60, check=True).stdout.decode()
    return {option for match in HELP_OPTION.finditer(text) for option in match.groups() if option}


def test_the_option_table_is_every_option_the_node_run_command_takes(node):
    assert help_options(node) - BUILT_IN_OPTIONS == set(lp.NODE_OPTIONS) - ALIASES


def test_export_blocks_is_given_exactly_the_options_it_shares_with_the_run_command(node):
    shared = help_options(node, "export-blocks") - BUILT_IN_OPTIONS - {"--from", "--to", "--binary"}
    passed = {option for option, (_, given) in lp.NODE_OPTIONS.items() if given}
    assert shared - {"--base-path", "-d"} == passed - ALIASES


def chain_database(base_path: Path, spec_path: Path) -> Path:
    return base_path / "chains" / json.loads(spec_path.read_text())["id"] / "db"


def run_node(node: Path, *words: str, cwd: Path) -> None:
    env = dict(lp.NODE_ENV, MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE=str(cwd / "registrations.json"))
    (cwd / "registrations.json").write_text("[]")
    subprocess.run([str(node), *words], cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=lp.NODE_TIMEOUT, check=True)


# The subcommands a launch may run before its node open no chain database, and one it may not writes one.
def test_only_the_subcommands_a_launch_may_run_before_its_node_leave_the_base_path_without_a_database(
        tmp_path, node, preprod):
    tools = {"build-spec": ["--raw", "--disable-default-bootnode"], "purge-chain": ["-y"]}
    assert tuple(tools) == lp.NODE_TOOLS
    base_path = tmp_path / "base"
    for tool, words in tools.items():
        run_node(node, tool, "--chain", str(preprod), "--base-path", str(base_path), *words, cwd=tmp_path)
        assert not chain_database(base_path, preprod).exists(), tool
    run_node(node, "export-blocks", "--chain", str(preprod), "--base-path", str(base_path), "--from", "0", "--to", "0",
             str(tmp_path / "block-0"), cwd=tmp_path)
    assert chain_database(base_path, preprod).is_dir()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def block_hash_answer(port: int) -> bytes:
    call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "chain_getBlockHash", "params": [0]}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}", call, {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as answer:
        return answer.read()


class RunningNode:
    """The real node's run command, offline: listeners on loopback only, no peers, no discovery, no telemetry or
    Prometheus, no keys, the mock follower, on a base path of the test's. Its chain spec names no boot node."""

    def __init__(self, node: Path, spec_path: Path, base_path: Path, cwd: Path):
        assert not json.loads(spec_path.read_text()).get("bootNodes")
        (cwd / "registrations.json").write_text("[]")
        self.port = free_port()
        argv = [str(node), "--chain", str(spec_path), "--base-path", str(base_path), "--no-telemetry",
                "--no-prometheus", "--no-mdns", "--reserved-only", "--in-peers", "0", "--out-peers", "0",
                "--in-peers-light", "0", "--listen-addr", "/ip4/127.0.0.1/tcp/0", "--rpc-port", str(self.port),
                "--rpc-methods", "safe"]
        env = dict(lp.NODE_ENV, MAIN_CHAIN_FOLLOWER_MOCK_REGISTRATIONS_FILE=str(cwd / "registrations.json"))
        self.log = cwd / "node.log"
        with open(self.log, "wb") as log:
            self.process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def served_genesis(self, path: Path) -> str:
        """Its answer to chain_getBlockHash [0], saved as an operator saves it with curl."""
        deadline = time.monotonic() + lp.NODE_TIMEOUT
        while time.monotonic() < deadline:
            assert self.process.poll() is None, self.log.read_text()[-2000:]
            try:
                path.write_bytes(block_hash_answer(self.port))
                return str(path)
            except OSError:
                time.sleep(1)
        raise AssertionError(f"the node answered nothing in {lp.NODE_TIMEOUT} seconds")

    def stop(self) -> None:
        self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(60)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def served_by_running_node(node: Path, spec_path: Path, base_path: Path, tmp_path: Path, swap: bytes | None = None,
                           name: str = "served") -> str:
    """What the node serves as block 0, started on `spec_path` over `base_path`; with `swap`, the spec file is
    overwritten with those bytes once the node runs, as a deployment tool syncing a final spec would."""
    cwd = tmp_path / name
    cwd.mkdir()
    running = RunningNode(node, spec_path, base_path, cwd)
    try:
        served = running.served_genesis(cwd / "genesis.json")
        if swap is not None:
            spec_path.write_bytes(swap)
            served = running.served_genesis(cwd / "genesis-after-swap.json")
        return served
    finally:
        running.stop()


def with_alice_as_root(preprod: Path, path: Path) -> Path:
    """The preprod spec with //Alice holding Root: the same chain id, another genesis."""
    doc = json.loads(preprod.read_text())
    doc["genesis"]["raw"]["top"]["0x" + lp.storage_key("Sudo", "Key").hex()] = "0x" + base.ALICE.hex()
    path.write_text(json.dumps(doc))
    return path


def test_a_running_node_on_a_fresh_base_path_serves_the_genesis_the_preflight_computes(tmp_path, node, pin, preprod):
    served = served_by_running_node(node, preprod, tmp_path / "base", tmp_path)
    entry = attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/mainnet-raw.json"], served=served)
    assert findings(preprod, entry) == []


def serves_other(genesis: bytes, preprod: Path) -> str:
    return (f"[8 node] authority val0: its running node serves genesis 0x{genesis.hex()} as block 0, and the "
            f"preflight computes 0x{lp.spec_genesis_hash(lp.load_spec(str(preprod))).hex()}: it started from another "
            "chain spec, or from a database its base path already held, not the chain the signed genesis hash and "
            "the lock's datum bind")


# The red team's stale database: a base path that already holds another genesis for the chain id, here written by
# the setup subcommand of their PoC, is what the node runs whatever its --chain names. A fresh start from its argv
# builds the checked genesis, so only what the running node serves shows it.
def test_a_running_node_whose_base_path_held_another_genesis_is_refused(tmp_path, node, pin, preprod):
    rehearsal = with_alice_as_root(preprod, tmp_path / "rehearsal-raw.json")
    base_path = tmp_path / "base"
    run_node(node, "export-blocks", "--chain", str(rehearsal), "--base-path", str(base_path), "--from", "0", "--to",
             "0", str(tmp_path / "block-0"), cwd=tmp_path)
    served = served_by_running_node(node, preprod, base_path, tmp_path)
    entry = attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/mainnet-raw.json"], served=served)
    assert findings(preprod, entry) == [serves_other(lp.spec_genesis_hash(lp.load_spec(str(rehearsal))), preprod)]


# The red team's swap: a node started on another spec keeps its genesis when its --chain file is overwritten with
# the checked spec, so every capture taken afterwards, but what it serves, is the checked launch's.
def test_a_running_node_whose_chain_spec_file_was_overwritten_after_it_started_is_refused(
        tmp_path, node, pin, preprod):
    started_on = with_alice_as_root(preprod, tmp_path / "mainnet-raw.json")
    rehearsal = lp.spec_genesis_hash(lp.load_spec(str(started_on)))
    served = served_by_running_node(node, started_on, tmp_path / "base", tmp_path, swap=preprod.read_bytes())
    assert started_on.read_bytes() == preprod.read_bytes()
    entry = attested(tmp_path, node, pin, preprod, ["--chain", "/srv/materios/mainnet-raw.json"], served=served)
    assert findings(preprod, entry) == [serves_other(rehearsal, preprod)]


def test_cli_passes_a_clean_launch_its_real_node_attests(clean, capsys, node, pin):
    for entry in clean.launch["nodes"]:
        if entry["authority"]:
            entry.update(exe=str(node), exe_sha256=pin)
    code, out = clean.run(capsys)
    assert (code, out.strip()) == (0, "MAINNET LAUNCH PREFLIGHT: PASS")


def test_cli_refuses_the_red_teams_chain_built_into_the_real_node(clean, capsys, node, pin):
    for entry in clean.launch["nodes"]:
        if entry["authority"]:
            entry.update(exe=str(node), exe_sha256=pin)
    base.with_node_argv(clean, ["--chain", "preprod"])
    code, out = clean.run(capsys)
    assert code == 1 and "[8 node] authority val0: --chain 'preprod' builds genesis 0x" in out, out
