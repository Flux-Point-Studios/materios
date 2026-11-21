"""Holds build.sh to its recipe.

build.sh runs here against a commit of a scratch repository, with a `docker`
on PATH that records what it was asked to run instead of building, so the
image, the container's commands and environment, and the archive fed to it
are checked without a toolchain.
"""

import gzip
import hashlib
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BUILD = HERE / "build.sh"
PREPROD_RAW = REPO / "tools/launch-preflight/fixtures/preprod-v6-raw.json.gz"
BLOB = "materios_runtime.compact.compressed.wasm"

FAKE_DOCKER = """#!/bin/sh
# Records its argv, NUL-separated, and its stdin, and writes the files the
# container would leave in the directory mounted at /out.
printf '%s\\0' "$@" > "$RECORD/argv"
cat > "$RECORD/stdin.tar"
for arg; do
	case $arg in *:/out) out=${arg%:/out} ;; esac
done
printf 'node bytes' > "$out/materios-node"
printf 'blob bytes' > "$out/materios_runtime.compact.compressed.wasm"
"""


def toolchain_channel():
    text = (REPO / "partnerchain/rust-toolchain.toml").read_text()
    return re.search(r'^channel = "([^"]+)"$', text, re.M).group(1)


@pytest.fixture
def scratch(tmp_path):
    repo = tmp_path / "repo"
    (repo / "partnerchain").mkdir(parents=True)
    (repo / "partnerchain/Cargo.toml").write_text("[workspace]\n")
    (repo / "outside.txt").write_text("not archived\n")
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "c"], check=True)
    commit = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True,
                            text=True).stdout.strip()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    record = tmp_path / "record"
    record.mkdir()
    return {"repo": repo, "commit": commit, "bin": bin_dir, "record": record, "tmp": tmp_path}


def run_build(scratch, *mode):
    out = scratch["tmp"] / "out"
    env = dict(os.environ, PATH=f"{scratch['bin']}:{os.environ['PATH']}",
               RECORD=str(scratch["record"]))
    result = subprocess.run(["sh", str(BUILD), *mode, scratch["commit"], str(out)],
                            cwd=scratch["repo"], env=env, check=True, capture_output=True,
                            text=True)
    argv = (scratch["record"] / "argv").read_text().split("\0")[:-1]
    return result.stdout, argv, out


def split_run(argv):
    """The docker run options, the image, and the script given to sh -euc."""
    image_at = next(i for i, a in enumerate(argv) if a.startswith("rust:"))
    assert argv[image_at + 1:image_at + 3] == ["sh", "-euc"]
    assert len(argv) == image_at + 4
    return argv[:image_at], argv[image_at], argv[image_at + 3]


def test_the_script_parses():
    subprocess.run(["sh", "-n", str(BUILD)], check=True)


def test_one_image_pinned_by_digest_at_the_toolchain_the_workspace_pins():
    images = re.findall(r"rust:[^\s\"']+", BUILD.read_text())
    assert images == [f"rust:{toolchain_channel()}-bookworm@sha256:{images[0][-64:]}"]
    assert re.fullmatch(r"[0-9a-f]{64}", images[0][-64:])


@pytest.mark.parametrize("mode", [(), ("--node",)])
def test_the_container_gets_the_commits_partnerchain_tree_alone(scratch, mode):
    run_build(scratch, *mode)
    stdin = scratch["record"] / "stdin.tar"
    with tarfile.open(stdin) as tar:
        names = tar.getnames()
    assert "partnerchain/Cargo.toml" in names
    assert all(n == "partnerchain" or n.startswith("partnerchain/") for n in names)
    recorded = subprocess.run(["git", "get-tar-commit-id"], stdin=stdin.open("rb"),
                              check=True, capture_output=True, text=True).stdout.strip()
    assert recorded == scratch["commit"]


def test_both_builds_share_the_image_and_preamble(scratch):
    _, runtime_argv, _ = run_build(scratch)
    _, node_argv, _ = run_build(scratch, "--node")
    _, runtime_image, runtime_script = split_run(runtime_argv)
    _, node_image, node_script = split_run(node_argv)
    assert runtime_image == node_image
    preamble = "cd /materios/partnerchain\n"
    assert preamble in runtime_script
    assert runtime_script.split(preamble)[0] == node_script.split(preamble)[0]
    assert "mkdir /materios\n\ttar -x -C /materios\n" in runtime_script


def test_the_runtime_build(scratch):
    stdout, argv, out = run_build(scratch)
    options, _, script = split_run(argv)
    assert options == ["run", "--rm", "-i", "-v", f"{out}:/out", "-e", "CARGO_BUILD_JOBS"]
    assert "nice -n 19 cargo check --locked --release -p materios-runtime\n" in script
    assert f"cp target/release/wbuild/materios-runtime/{BLOB} /out/\n" in script
    blob = b"blob bytes"
    assert stdout.splitlines() == [
        f"commit     {scratch['commit']}",
        f"blob       {out}/{BLOB}",
        f"sha256     {hashlib.sha256(blob).hexdigest()}",
        f"blake2-256 0x{hashlib.blake2b(blob, digest_size=32).hexdigest()}",
    ]


def test_the_node_build_names_the_archived_commit_in_its_version(scratch):
    stdout, argv, out = run_build(scratch, "--node")
    options, _, script = split_run(argv)
    assert options == ["run", "--rm", "-i", "-v", f"{out}:/out", "-e", "CARGO_BUILD_JOBS",
                       "--platform", "linux/amd64",
                       "-e", f"SUBSTRATE_CLI_GIT_COMMIT_HASH={scratch['commit'][:11]}"]
    assert "nice -n 19 cargo build --locked --release -p materios-node\n" in script
    assert "cp target/release/materios-node /out/\n" in script
    node, blob = b"node bytes", b"blob bytes"
    assert stdout.splitlines() == [
        f"commit     {scratch['commit']}",
        f"node       {out}/materios-node",
        f"sha256     {hashlib.sha256(node).hexdigest()}",
        f"blob       {out}/{BLOB}",
        f"sha256     {hashlib.sha256(blob).hexdigest()}",
        f"blake2-256 0x{hashlib.blake2b(blob, digest_size=32).hexdigest()}",
    ]


def extraction(script, out):
    """The node build's lines from its build-spec to the cmp of its :code,
    with /out moved to a directory of the test's."""
    lines = script.split("\n")
    start = next(i for i, l in enumerate(lines) if "materios-node build-spec" in l)
    end = next(i for i, l in enumerate(lines) if l.strip().startswith("cmp "))
    return "\n".join(lines[start:end + 1]).replace("/out/", f"{out}/")


@pytest.mark.parametrize("embedded_matches", [True, False])
def test_the_node_build_takes_code_from_the_nodes_own_build_spec(scratch, tmp_path,
                                                                 embedded_matches):
    _, argv, _ = run_build(scratch, "--node")
    _, _, script = split_run(argv)
    raw = gzip.decompress(PREPROD_RAW.read_bytes())
    code = bytes.fromhex(json.loads(raw)["genesis"]["raw"]["top"]["0x3a636f6465"][2:])
    work = tmp_path / "work"
    (work / "target/release/wbuild/materios-runtime").mkdir(parents=True)
    (work / "raw.json").write_bytes(raw)
    node = work / "target/release/materios-node"
    node.write_text('#!/bin/sh\n[ "$*" = "build-spec --chain preprod --raw" ] && cat "$(dirname "$0")/../../raw.json"\n')
    node.chmod(0o755)
    (work / "target/release/wbuild/materios-runtime" / BLOB).write_bytes(
        code if embedded_matches else code[:-1] + bytes([code[-1] ^ 1]))
    result = subprocess.run(["sh", "-euc", extraction(script, work)], cwd=work,
                            capture_output=True)
    assert (work / BLOB).read_bytes() == code
    assert (result.returncode == 0) == embedded_matches
