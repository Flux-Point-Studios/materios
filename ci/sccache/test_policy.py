"""The cache's write policy, read from the workflows themselves.

The server refuses the reader's writes and Woodpecker withholds the writer's
secret from pull_request pipelines (README.md); these tests keep the
workflows from asking for anything else, and keep the pull request build and
the main build computing the same cache keys.
"""
from pathlib import Path
import re
import unittest

from cryptography import x509
import yaml

ROOT = Path(__file__).resolve().parents[2]
CLIENT = re.compile(r"^\. (\.\./)*ci/sccache/client\.sh$")
ENDPOINT = "https://192.168.0.133:3910"
READER = {
    "SCCACHE_WEBDAV_USERNAME": "sccache-reader",
    "SCCACHE_WEBDAV_PASSWORD": {"from_secret": "sccache_reader_password"},
    "SCCACHE_WEBDAV_RW_MODE": "READ_ONLY",
}
WRITER = {
    "SCCACHE_WEBDAV_USERNAME": "sccache-writer",
    "SCCACHE_WEBDAV_PASSWORD": {"from_secret": "sccache_writer_password"},
}
PULL_REQUEST = [{"event": "pull_request"}]
PUSH_TO_MAIN = [{"event": "push", "branch": "main"}]


def workflows():
    for path in sorted((ROOT / ".woodpecker").glob("*.yaml")):
        yield path.name, yaml.safe_load(path.read_text())


def as_list(value):
    return value if isinstance(value, list) else [value]


def cached_steps(workflow):
    return [s for s in workflow["steps"] if any(CLIENT.match(c) for c in s.get("commands", []))]


def role(step):
    return {k: v for k, v in step.get("environment", {}).items() if k in READER}


def build(step):
    environment = {k: v for k, v in step.get("environment", {}).items() if k not in READER}
    return {"image": step["image"], "directory": step.get("directory"),
            "commands": step["commands"], "environment": environment}


class WritePolicy(unittest.TestCase):
    def test_rust_check_test_reads_on_pull_requests_and_writes_on_main(self):
        rust = dict(workflows())["rust.yaml"]
        self.assertEqual({s["name"]: as_list(s["when"]) for s in cached_steps(rust)},
                         {"check-test": PULL_REQUEST, "check-test-main": PUSH_TO_MAIN})

    def test_writer_secret_is_asked_for_only_on_pushes_to_main(self):
        for name, workflow in workflows():
            for step in workflow["steps"]:
                if "sccache_writer_password" in repr(step):
                    with self.subTest(workflow=name, step=step["name"]):
                        self.assertEqual(as_list(step.get("when")), PUSH_TO_MAIN)
                        self.assertEqual(role(step), WRITER)
                        self.assertTrue(all(c.get("branch") == "main" for c in as_list(workflow["when"])))

    def test_every_cached_step_is_a_reader_on_pull_requests_or_the_writer_on_main(self):
        for name, workflow in workflows():
            for step in cached_steps(workflow):
                with self.subTest(workflow=name, step=step["name"]):
                    expected = {str(PULL_REQUEST): READER, str(PUSH_TO_MAIN): WRITER}
                    self.assertEqual(role(step), expected.get(str(as_list(step.get("when")))))

    def test_pull_request_and_main_builds_compute_the_same_keys(self):
        for name, workflow in workflows():
            steps = cached_steps(workflow)
            if not steps:
                continue
            with self.subTest(workflow=name):
                self.assertEqual(len(steps), 2)
                reader, writer = sorted(steps, key=lambda s: s["name"])
                self.assertEqual(build(reader), build(writer))
                self.assertEqual(build(reader)["environment"].get("SCCACHE_WEBDAV_ENDPOINT"), ENDPOINT)
                # sccache can only cache non-incremental rustc runs.
                self.assertEqual(build(reader)["environment"].get("CARGO_INCREMENTAL"), "0")

    def test_pinned_ca_vouches_only_for_the_store(self):
        ca = x509.load_pem_x509_certificate((ROOT / "ci/sccache/ca.pem").read_bytes())
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        constraints = ca.extensions.get_extension_for_class(x509.NameConstraints)
        self.assertTrue(constraints.critical)
        # The reserved "invalid" domain admits no real DNS name.
        self.assertEqual([str(n.value) for n in constraints.value.permitted_subtrees],
                         ["192.168.0.133/32", "invalid"])


if __name__ == "__main__":
    unittest.main()
