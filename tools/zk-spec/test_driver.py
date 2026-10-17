import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import check


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = check.Driver(check.ROOT)

    def test_unknown_operation_is_nonzero(self):
        with self.assertRaisesRegex(check.CheckFailure, 'no implemented production path'):
            self.driver.query('unknown-operation', {})

    def test_missing_artifacts_are_nonzero(self):
        if self.driver.binary is None:
            with self.assertRaises(check.CheckFailure):
                self.driver.query('unknown-operation', {})
        with tempfile.TemporaryDirectory() as directory:
            request = json.dumps({'version': 1, 'operation': 'p0-metadata-compat', 'payload': {}})
            result = subprocess.run([str(self.driver.binary)], input=request, text=True,
                cwd=directory, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_invalid_protocol_is_nonzero(self):
        if self.driver.binary is None:
            with self.assertRaises(check.CheckFailure):
                self.driver.query('unknown-operation', {})
        for request in ({}, {'version': True, 'operation': 'p0-bridge-codec', 'payload': {}},
                        {'version': 1, 'operation': 'p0-bridge-codec', 'payload': [], 'extra': 1}):
            result = subprocess.run([str(self.driver.binary)], input=json.dumps(request), text=True,
                cwd=check.ROOT, capture_output=True, check=False)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
