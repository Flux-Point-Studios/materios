import copy
import json
import unittest
import p0_tools


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.mac = json.loads((p0_tools.ROOT/'docs/native-zk-evidence/p0-macbook.json').read_text())

    def test_matching_mac_capture_is_usable(self):
        p0_tools.validate_macbook(self.mac, self.mac['wasm_sha256'])

    def test_stale_binary_or_empty_samples_are_refused(self):
        with self.assertRaises(ValueError):
            p0_tools.validate_macbook(self.mac, '0'*64)
        changed = copy.deepcopy(self.mac)
        changed['milliseconds'] = []
        with self.assertRaises(ValueError):
            p0_tools.validate_macbook(changed, self.mac['wasm_sha256'])

    def test_wrong_architecture_and_failed_vectors_are_refused(self):
        for change in ('architecture', 'proof'):
            changed = copy.deepcopy(self.mac)
            if change == 'architecture': changed['hardware']['arch'] = 'x64'
            else: changed['vectors'][0]['accepted'] = False
            with self.assertRaises(ValueError):
                p0_tools.validate_macbook(changed, self.mac['wasm_sha256'])


if __name__ == '__main__':
    unittest.main()
