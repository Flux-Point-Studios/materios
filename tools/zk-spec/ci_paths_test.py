import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
CLI = os.environ.get("WOODPECKER_CLI", "woodpecker-cli")
CHEAP = {"p0-primitives"}
ALL = CHEAP | {"c-p0-sapling-spike"}


class CIPathsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load((ROOT / ".woodpecker/zk-p0.yaml").read_text())

    def selected(self, files, event="pull_request", branch="main"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "selected"
            workflow = copy.deepcopy(self.workflow)
            workflow["skip_clone"] = True
            # Execute the real conditions with harmless local marker commands.
            for step in workflow["steps"]:
                step["image"] = "bash"
                step["commands"] = [
                    f"printf '%s\\n' {shlex.quote(step['name'])} >> {shlex.quote(str(output))}"
                ]
            config = root / "zk-p0.yaml"
            config.write_text(yaml.safe_dump(workflow))
            result = subprocess.run([
                CLI, "--disable-update-check", "exec", "--backend-engine", "local",
                "--local", "--repo-path", directory, "--pipeline-event", event,
                "--commit-branch", branch, "--pipeline-changed-files", json.dumps(files),
                str(config),
            ], text=True, capture_output=True, timeout=30)
            if result.returncode:
                self.assertIn("no workflows to execute (all filtered out)", result.stderr)
                self.assertFalse(output.exists(), result.stdout + result.stderr)
                return set()
            self.assertTrue(output.exists(), result.stdout + result.stderr)
            return set(output.read_text().splitlines())

    def test_zk_and_spec_changes_run_both_steps(self):
        for event in ("push", "pull_request"):
            for path in ("tools/zk-spec/ci.sh", "tools/zk-spec/core/src/lib.rs",
                         ".fluxpoint-spec.json", ".fluxpoint-spec-lock.json"):
                with self.subTest(event=event, path=path):
                    self.assertEqual(self.selected([path], event), ALL)

    def test_runtime_chain_and_harness_changes_run_only_cheap_step(self):
        for event in ("push", "pull_request"):
            for path in ("WORK.md", "scripts/harness.sh", ".woodpecker/zk-p0.yaml",
                         "partnerchain/runtime/Cargo.toml", "partnerchain/runtime/src/lib.rs",
                         "partnerchain/pallets/motra/src/lib.rs", "chain-spec/mainnet.json",
                         "chain-spec/nested/preprod.json"):
                with self.subTest(event=event, path=path):
                    self.assertEqual(self.selected([path], event), CHEAP)

    def test_docs_only_and_unrelated_changes_select_nothing(self):
        for event in ("push", "pull_request"):
            for files in (["README.md", "docs/native-zk-p0.md"],
                          ["tools/seat-keys/README.md"], ["scripts/other.sh"],
                          ["tools/zk-spec-extra/main.rs"], ["chain-specs/mainnet.json"],
                          [".fluxpoint-spec.json.bak"], [".woodpecker/rust.yaml"]):
                with self.subTest(event=event, files=files):
                    self.assertEqual(self.selected(files, event), set())

    def test_empty_changes_select_nothing(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                self.assertEqual(self.selected([], event), set())

    def test_pr_uses_whole_diff_and_accepts_stacked_base(self):
        self.assertEqual(self.selected(["docs/guide.md", "tools/zk-spec/core/src/lib.rs"],
                                       branch="spec/native-zk-hybrid"), ALL)
        self.assertEqual(self.selected(["README.md", "partnerchain/runtime/src/lib.rs"]), CHEAP)

    def test_feature_pushes_and_other_events_select_nothing(self):
        for event, branch in (("push", "impl/native-zk-p0"), ("tag", "main"),
                              ("manual", "main"), ("cron", "main")):
            with self.subTest(event=event, branch=branch):
                self.assertEqual(self.selected(["tools/zk-spec/core/src/lib.rs"], event, branch), set())

    def test_cheap_script_does_not_execute_sapling_work(self):
        script = (ROOT / "tools/zk-spec/ci.sh").read_text()
        self.assertNotIn("wasm-run.mjs", script)
        self.assertNotIn("tools/zk-spec/wasm/Cargo.toml", script)
        for check in ("c-p0-mainnet-refusal", "c-p0-midnight-negative-control", "c-p0-bridge-codec"):
            self.assertIn(f"check.py {check}", script)
        spike = next(step for step in self.workflow["steps"] if step["name"] == "c-p0-sapling-spike")
        self.assertIn("tools/zk-spec/ci-sapling.sh", spike["commands"])
        rust = (ROOT / ".woodpecker/rust.yaml").read_text()
        self.assertIn("p0_tools.py metadata-compat", rust)


if __name__ == "__main__":
    unittest.main(verbosity=2)
