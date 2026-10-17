import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check


class AdapterTests(unittest.TestCase):
    def test_empty_suite_fails(self):
        self.assertEqual(check.run_suite(unittest.TestSuite(), io.StringIO()), 1)

    def test_skipped_suite_fails(self):
        class Skipped(unittest.TestCase):
            @unittest.skip("unavailable dependency")
            def test_item(self):
                pass
        self.assertEqual(check.run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Skipped), io.StringIO()), 1)

    def test_expected_failure_is_not_green(self):
        class Expected(unittest.TestCase):
            @unittest.expectedFailure
            def test_item(self):
                self.fail("missing behavior")
        self.assertEqual(check.run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Expected), io.StringIO()), 1)

    def test_real_assertion_passes(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: self.assertEqual(2 + 2, 4))])
        self.assertEqual(check.run_suite(suite, io.StringIO()), 0)

    def test_assertion_failure_is_red(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: self.fail("mutation"))])
        self.assertEqual(check.run_suite(suite, io.StringIO()), 1)

    def test_missing_command_fails(self):
        with patch("check.subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(check.CheckFailure, "missing dependency"):
                check.run_argv(["missing"], Path.cwd())

    def test_timeout_fails(self):
        with patch("check.subprocess.run", side_effect=subprocess.TimeoutExpired(["test"], 1)):
            with self.assertRaisesRegex(check.CheckFailure, "timeout"):
                check.run_argv(["test"], Path.cwd())

    def test_nonzero_exit_fails(self):
        with patch("check.subprocess.run", return_value=subprocess.CompletedProcess(["test"], 7, "", "")):
            with self.assertRaisesRegex(check.CheckFailure, "exit 7"):
                check.run_argv(["test"], Path.cwd())

    def test_argv_is_literal_and_target_is_worktree_local(self):
        with patch("check.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            self.assertEqual(check.run_argv(["test", "$(false)"], Path.cwd()), "ok")
            args, kwargs = run.call_args
            self.assertEqual(args[0], ["test", "$(false)"])
            self.assertFalse(kwargs.get("shell", False))
            self.assertEqual(kwargs["env"]["CARGO_TARGET_DIR"], str(Path.cwd() / ".zk-spec-target"))

    def test_cargo_zero_tests_fails(self):
        with self.assertRaisesRegex(check.CheckFailure, "exactly one"):
            check.assert_one_cargo_test("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out")

    def test_cargo_ignored_test_fails(self):
        with self.assertRaises(check.CheckFailure):
            check.assert_one_cargo_test("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 8 filtered out")

    def test_cargo_missing_summary_fails(self):
        with self.assertRaises(check.CheckFailure):
            check.assert_one_cargo_test("all good")

    def test_cargo_single_real_test_passes(self):
        check.assert_one_cargo_test("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out")

    def test_absent_aj_tests_fail_before_compiling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "partnerchain/pallets/motra/src/tests.rs"
            source.parent.mkdir(parents=True)
            source.write_text("#[test]\nfn unrelated() {}\n")
            with patch("check.run_argv") as run:
                with self.assertRaisesRegex(check.CheckFailure, "AJ tests missing"):
                    check.motra66(root)
                run.assert_not_called()

    def test_absent_driver_fails_before_compiling(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(check.CheckFailure, "runtime driver missing"):
                check.Driver(Path(directory)).query("snapshot", {})

    def test_driver_empty_response_fails(self):
        driver = check.Driver(Path.cwd())
        driver.binary = Path("already-built")
        with patch("check.run_argv", return_value="{}"):
            with self.assertRaisesRegex(check.CheckFailure, "driver response"):
                driver.query("snapshot", {})

    def test_driver_unknown_response_fails(self):
        driver = check.Driver(Path.cwd())
        driver.binary = Path("already-built")
        with patch("check.run_argv", return_value='{"version":1,"result":null}'):
            with self.assertRaisesRegex(check.CheckFailure, "driver response"):
                driver.query("snapshot", {})

    def test_boolean_protocol_version_is_not_integer_version(self):
        driver = check.Driver(Path.cwd())
        driver.binary = Path("already-built")
        with patch("check.run_argv", return_value='{"version":true,"result":{}}'):
            with self.assertRaisesRegex(check.CheckFailure, "driver response"):
                driver.query("snapshot", {})

    def test_duplicate_response_keys_fail(self):
        driver = check.Driver(Path.cwd())
        driver.binary = Path("already-built")
        with patch("check.run_argv", return_value='{"version":0,"version":1,"result":{}}'):
            with self.assertRaisesRegex(check.CheckFailure, "duplicate"):
                driver.query("snapshot", {})

    def test_unknown_driver_status_fails(self):
        driver = check.Driver(Path.cwd())
        driver.binary = Path("already-built")
        with patch("check.run_argv", return_value='{"version":1,"result":{"status":"unknown"}}'):
            with self.assertRaisesRegex(check.CheckFailure, "unknown"):
                driver.query("snapshot", {})


if __name__ == "__main__":
    unittest.main()
