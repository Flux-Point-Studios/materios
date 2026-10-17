#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
AJ_TESTS = (
    "accrual_fresh_account_starts_at_funding",
    "accrual_cycling_ten_accounts_cannot_multiply_generation",
    "accrual_top_up_does_not_backdate_holdings",
    "accrual_sovereign_accounts_never_generate",
    "accrual_projection_matches_safe_reconciliation",
    "accrual_account_creation_initializes_clock",
    "accrual_round_trip_cannot_restore_spent_interval",
    "accrual_sovereign_cannot_generate_for_delegatee",
)


class CheckFailure(RuntimeError):
    pass


def driver_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CheckFailure("duplicate driver response key")
        if key == "status" and value != "complete":
            raise CheckFailure("unknown or incomplete driver status")
        result[key] = value
    return result


def run_argv(argv, root, timeout=300, input_text=None):
    env = dict(os.environ, CARGO_TARGET_DIR=str(root / ".zk-spec-target"), CARGO_BUILD_JOBS="2")
    try:
        result = subprocess.run(argv, cwd=root, env=env, input=input_text,
                                capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        raise CheckFailure(f"missing dependency: {argv[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise CheckFailure(f"timeout after {timeout}s: {argv[0]}") from error
    if result.returncode:
        raise CheckFailure(f"command exit {result.returncode}: {argv[0]}: {result.stderr[-1200:]}")
    return result.stdout


def assert_one_cargo_test(output):
    summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;", output)
    if summaries != [("1", "0", "0", "0")]:
        raise CheckFailure("expected exactly one passing, non-ignored Cargo test")


def motra66(root):
    source = root / "partnerchain/pallets/motra/src/tests.rs"
    if not source.is_file():
        raise CheckFailure("AJ test source missing")
    names = set(re.findall(r"\bfn\s+(accrual_\w+)\s*\(", source.read_text()))
    missing = sorted(set(AJ_TESTS) - names)
    if missing:
        raise CheckFailure("AJ tests missing: " + ", ".join(missing))
    command = ["nice", "-n", "10", "cargo", "+1.85.0", "test", "--locked", "--offline",
               "--manifest-path", "partnerchain/Cargo.toml", "-p", "pallet-motra", "--lib"]
    listing = run_argv(command + ["--", "--list"], root, timeout=1800)
    compiled = set(re.findall(r"^(tests::\w+): test$", listing, re.M))
    if any("tests::" + name not in compiled for name in AJ_TESTS):
        raise CheckFailure("AJ source names are not compiled runnable tests")
    for name in AJ_TESTS:
        output = run_argv(command + ["tests::" + name, "--", "--exact"], root, timeout=120)
        assert_one_cargo_test(output)
        print(f"AJ: tests::{name}: 1 passed", flush=True)
    print(f"AJ: {len(AJ_TESTS)} exact tests passed; genesis inclusion remains a separate check")


class Driver:
    def __init__(self, root):
        self.root = root
        self.binary = None

    def query(self, operation, payload):
        if self.binary is None:
            manifest = self.root / "tools/zk-spec/driver/Cargo.toml"
            if not manifest.is_file():
                raise CheckFailure("runtime driver missing: tools/zk-spec/driver/Cargo.toml; no implementation checked")
            run_argv(["nice", "-n", "10", "cargo", "+1.85.0", "build", "--locked", "--offline",
                      "--manifest-path", str(manifest)], self.root, timeout=1800)
            self.binary = self.root / ".zk-spec-target/debug/materios-zk-spec-driver"
        output = run_argv([str(self.binary)], self.root, timeout=3600 if operation.startswith("p0-") else 300,
                          input_text=json.dumps({"version": 1, "operation": operation, "payload": payload}))
        try:
            response = json.loads(output, object_pairs_hook=driver_object)
        except json.JSONDecodeError as error:
            raise CheckFailure("invalid driver response JSON") from error
        if (not isinstance(response, dict) or type(response.get("version")) is not int
                or response["version"] != 1 or not isinstance(response.get("result"), dict)):
            raise CheckFailure("invalid driver response; unknown is not success")
        return response["result"]


def run_suite(suite, stream):
    expected = suite.countTestCases()
    if expected == 0:
        stream.write("RED: zero tests selected\n")
        return 1
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    passed = (result.wasSuccessful() and result.testsRun == expected
              and not result.skipped and not result.expectedFailures)
    stream.write(f"{'GREEN' if passed else 'RED'}: selected={expected} ran={result.testsRun} skipped={len(result.skipped)}\n")
    return 0 if passed else 1


def main():
    from contracts import SUITES
    from p0_contracts import P0_SUITES
    suites = {**SUITES, **P0_SUITES}
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=sorted([*suites, "c-motra-66"]))
    args = parser.parse_args()
    if Path.cwd().resolve() != ROOT:
        parser.error("run from the repository root")
    try:
        if args.check == "c-motra-66":
            motra66(ROOT)
            return 0
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(suites[args.check])
        return run_suite(suite, sys.stdout)
    except (CheckFailure, OSError, ValueError) as error:
        print(f"RED {args.check}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
