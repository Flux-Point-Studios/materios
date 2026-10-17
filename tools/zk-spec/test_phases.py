import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PhaseTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("phases", ROOT / "tools/zk-spec/phases.py")
        self.phases = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.phases)
        self.packet = json.loads((ROOT / ".fluxpoint-spec.json").read_text())

    def test_p0_selects_exact_six_checks(self):
        selected = self.phases.select(self.packet, "CURRENT_PHASE: P0\n", False)
        self.assertCountEqual([c["id"] for c in selected], [
            "c-p0-core-no-egress", "c-p0-midnight-negative-control", "c-p0-mainnet-refusal",
            "c-p0-metadata-compat", "c-p0-bridge-codec", "c-p0-sapling-spike"])

    def test_all_keeps_every_obligation(self):
        self.assertEqual(self.phases.select(self.packet, "CURRENT_PHASE: P0\n", True),
                         self.packet["checks"])

    def test_original_checks_and_acceptance_are_unchanged(self):
        original = json.loads(subprocess.check_output(
            ["git", "show", "5460448:.fluxpoint-spec.json"], cwd=ROOT))
        current = {c["id"]: c for c in self.packet["checks"]}
        for check in original["checks"]:
            candidate = copy.deepcopy(current[check["id"]])
            candidate["scope"] = candidate["scope"].split(". ", 1)[1]
            self.assertEqual(candidate, check)
        before = subprocess.check_output(["git", "show", "5460448:tools/zk-spec/contracts.py"], cwd=ROOT)
        self.assertEqual((ROOT / "tools/zk-spec/contracts.py").read_bytes(), before)
        reqs = {r["id"]: r for r in self.packet["requirements"]}
        for requirement in original["requirements"]:
            self.assertEqual(reqs[requirement["id"]], requirement)

    def test_missing_invalid_or_duplicate_current_phase_refuses(self):
        for work in ("", "CURRENT_PHASE: P6", "CURRENT_PHASE: P0\nCURRENT_PHASE: P1"):
            with self.assertRaises(ValueError):
                self.phases.select(self.packet, work, False)

    def test_missing_or_unknown_check_phase_refuses_even_all(self):
        for scope in ("missing", "Phase P6. unknown"):
            packet = copy.deepcopy(self.packet)
            packet["checks"][0]["scope"] = scope
            with self.assertRaises(ValueError):
                self.phases.select(packet, "CURRENT_PHASE: P0\n", True)


if __name__ == "__main__":
    unittest.main()
