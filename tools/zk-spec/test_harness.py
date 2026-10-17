import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Harness Test")
        self.git("config", "user.email", "harness@example.invalid")
        self.write("scripts/harness.sh", (ROOT / "scripts/harness.sh").read_text())
        self.write("plugin/scripts/specification.py", "")
        self.write("plugin/scripts/py.sh", 'echo "SPEC $*"\nexit "${TEST_SPEC_EXIT:-0}"\n')
        self.write("tools/zk-spec/test_smoke.py", """import os
import unittest

class SmokeTests(unittest.TestCase):
    def test_always_run(self):
        print('UNIT')
        self.assertEqual(os.environ.get('TEST_UNIT_FAIL', '0'), '0')
""")
        self.write("tools/zk-spec/phases.py", """import os
import sys
print('PHASES ' + ' '.join(sys.argv[1:]))
sys.exit(int(os.environ.get('TEST_PHASE_EXIT', '0')))
""")
        self.write("tools/zk-spec/tracked.txt", "baseline\n")
        self.write("partnerchain/pallets/motra/src/lib.rs", "baseline\n")
        self.write(".fluxpoint-spec.json", "baseline\n")
        self.write(".fluxpoint-spec-lock.json", "baseline\n")
        self.write(".gitignore", "__pycache__/\n.zk-spec-target/\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.base)
        self.env = dict(os.environ, FPL_PLUGIN_ROOT=str(self.root / "plugin"))
        self.env.pop("FPL_DIFF_BASE", None)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True,
                                       stderr=subprocess.PIPE).strip()

    def write(self, path, content="changed\n"):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def commit(self):
        self.git("add", "--all")
        self.git("-c", "commit.gpgsign=false", "commit", "-m", "fixture")

    def run_harness(self, mode="--full", **env):
        return subprocess.run(["bash", "scripts/harness.sh", mode], cwd=self.root,
                              env=dict(self.env, **env), text=True, capture_output=True, timeout=30)

    def assert_not_selected(self, result, base):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SPEC specification.py --check", result.stdout)
        self.assertIn("UNIT", result.stdout)
        self.assertNotIn("PHASES", result.stdout)
        self.assertIn(f"harness: base={base}; P0 phase checks were not selected", result.stdout)

    def test_runtime_only_runs_always_checks_without_artifacts(self):
        self.write("partnerchain/pallets/motra/src/lib.rs")
        self.assertFalse((self.root / ".zk-spec-target").exists())
        self.assertFalse((self.root / "tools/zk-spec/artifacts").exists())
        self.assert_not_selected(self.run_harness(), self.base)

    def test_explicit_base_excludes_earlier_zk_changes(self):
        self.write("tools/zk-spec/tracked.txt")
        self.commit()
        session_base = self.git("rev-parse", "HEAD")
        self.write("partnerchain/pallets/motra/src/lib.rs")
        self.assert_not_selected(self.run_harness(FPL_DIFF_BASE=session_base), session_base)
        self.assertIn("PHASES", self.run_harness().stdout)

    def test_fallback_uses_merge_base_not_origin_tip(self):
        self.git("checkout", "-b", "upstream")
        self.write("tools/zk-spec/tracked.txt")
        self.commit()
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git("checkout", "main")
        self.write("partnerchain/pallets/motra/src/lib.rs")
        self.commit()
        self.assert_not_selected(self.run_harness(), self.base)

    def test_zk_edits_select_phases_in_every_git_state(self):
        for state in ("unstaged", "staged", "committed", "untracked"):
            with self.subTest(state=state):
                path = f"tools/zk-spec/{state}.txt"
                self.write(path)
                if state != "untracked":
                    self.git("add", path)
                    self.git("-c", "commit.gpgsign=false", "commit", "-m", "add path")
                    self.env["FPL_DIFF_BASE"] = self.git("rev-parse", "HEAD")
                    self.write(path, "second version\n")
                    if state in ("staged", "committed"):
                        self.git("add", path)
                    if state == "committed":
                        self.git("-c", "commit.gpgsign=false", "commit", "-m", "edit path")
                result = self.run_harness()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("UNIT", result.stdout)
                self.assertIn("PHASES", result.stdout)
                if state != "committed":
                    self.commit()
                self.env["FPL_DIFF_BASE"] = self.git("rev-parse", "HEAD")

    def test_spec_files_select_phases(self):
        for path in (".fluxpoint-spec.json", ".fluxpoint-spec-lock.json"):
            with self.subTest(path=path):
                self.write(path)
                self.assertIn("PHASES", self.run_harness().stdout)
                self.git("restore", path)

    def test_deleted_or_renamed_out_zk_path_selects_phases(self):
        self.git("mv", "tools/zk-spec/tracked.txt", "outside.txt")
        self.assertIn("PHASES", self.run_harness().stdout)
        (self.root / "outside.txt").unlink()
        self.assertIn("PHASES", self.run_harness().stdout)

    def test_untracked_newline_path_selects_phases(self):
        self.write("tools/zk-spec/new\nfile.txt")
        self.assertIn("PHASES", self.run_harness().stdout)

    def test_similar_paths_and_ignored_artifacts_do_not_select(self):
        for path in ("tools/zk-spec-extra/file.py", ".fluxpoint-spec.json.bak",
                     "docs/guide.md", ".zk-spec-target/cache"):
            self.write(path)
        self.assert_not_selected(self.run_harness(), self.base)

    def test_bad_or_missing_base_fails_closed_after_always_checks(self):
        for base in ("not-a-revision", ""):
            with self.subTest(base=base):
                if not base:
                    self.git("update-ref", "-d", "refs/remotes/origin/main")
                result = self.run_harness(FPL_DIFF_BASE=base)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("UNIT", result.stdout)
                self.assertNotIn("PHASES", result.stdout)
                self.assertNotIn("were not selected", result.stdout)

    def test_always_checks_fail_closed(self):
        for env in ({"TEST_SPEC_EXIT": "7"}, {"TEST_UNIT_FAIL": "1"}):
            with self.subTest(env=env):
                result = self.run_harness(**env)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("PHASES", result.stdout)
                self.assertNotIn("were not selected", result.stdout)

    def test_all_runs_phases_without_diff_base_and_preserves_failure(self):
        result = self.run_harness("--all", FPL_DIFF_BASE="invalid", TEST_PHASE_EXIT="9")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertIn("UNIT", result.stdout)
        self.assertIn("PHASES --all", result.stdout)

    def test_selected_phase_failure_is_not_swallowed(self):
        self.write("tools/zk-spec/tracked.txt")
        result = self.run_harness(TEST_PHASE_EXIT="9")
        self.assertEqual(result.returncode, 9, result.stderr)

    def test_spec_check_only_checks_lock(self):
        result = self.run_harness("--spec-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SPEC specification.py --check", result.stdout)
        self.assertNotIn("UNIT", result.stdout)
        self.assertNotIn("PHASES", result.stdout)


if __name__ == "__main__":
    unittest.main()
