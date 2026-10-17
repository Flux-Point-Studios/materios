import unittest
from check import Driver, ROOT

DRIVER = Driver(ROOT)


class CoreNoEgress(unittest.TestCase):
    def test_core_build_and_real_tests_without_network(self):
        r = DRIVER.query('p0-core-no-egress', {})
        self.assertNotEqual(r['host_netns_inode'], r['test_netns_inode'])
        self.assertEqual(r['external_routes'], [])
        self.assertEqual(set(r['denied_probes']), {'srs.midnight.network', 'node.midnight.network', 'direct-ip'})
        self.assertTrue(all(code != 0 for code in r['denied_probes'].values()))
        self.assertGreaterEqual(r['tests_passed'], 3)
        self.assertTrue(r['compiled_packages'])
        self.assertTrue(any('materios-zk-core' in package for package in r['compiled_packages']))
        self.assertEqual((r['build_exit'], r['test_exit']), (0, 0))
        self.assertTrue(r['packages'])
        self.assertFalse(any('midnight' in name.lower() for name in r['packages']))
        self.assertEqual(r['midnight_dependencies'], [])


class MidnightNegativeControl(unittest.TestCase):
    def test_injected_dependency_fails_exclusion_gate(self):
        r = DRIVER.query('p0-midnight-negative-control', {})
        self.assertEqual(r['injected'], 'midnight-negative-control')
        self.assertNotEqual(r['gate_exit'], 0)
        self.assertEqual(r['reason'], 'Midnight dependency: midnight-negative-control')


class MainnetRefusal(unittest.TestCase):
    def test_source_routes_refuse_mainnet_and_impersonation(self):
        r = DRIVER.query('p0-mainnet-refusal', {})
        self.assertRegex(r['inventory']['source_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual({t['format'] for t in r['inventory']['mainnet']}, {'plain', 'raw'})
        expected = r['inventory']['mainnet'] + r['inventory']['preprod'] + [r['inventory']['file_alias_probe']]
        self.assertEqual([c['target'] for c in r['cases']], expected)
        for case in r['cases']:
            self.assertIs(case['allowed'], case['target']['route'] == 'preprod')
        self.assertEqual(set(r['mutants']), {'allow-file-mainnet', 'id-only-preprod-alias'})
        for mutant in r['mutants'].values():
            self.assertNotEqual(mutant['test_exit'], 0)
            self.assertGreater(mutant['failed_assertions'], 0)


class MetadataCompat(unittest.TestCase):
    def test_actual_runtime_against_explicit_source_baseline_and_mutants(self):
        r = DRIVER.query('p0-metadata-compat', {})
        self.assertIn('52829ca46323cf22b3e0feece3adc33cb4edb095', r['baseline_identity'])
        self.assertRegex(r['baseline_metadata_sha256'], r'^[0-9a-f]{64}$')
        self.assertRegex(r['runtime_sha256'], r'^[0-9a-f]{64}$')
        self.assertGreater(r['source_files_checked'], 0)
        self.assertGreater(r['old_pallets'], 0)
        self.assertEqual(r['old_pallets'], r['new_pallets'])
        self.assertEqual(r['gate_exit'], 0, r['violations'])
        self.assertEqual(r['runtime_version']['transactionVersion'], 5)
        self.assertEqual(set(r['mutants']), {'insert-error-in-middle', 'insert-event-in-middle',
            'reuse-pallet-index', 'change-signed-extra', 'stale-manifest', 'shrink-bound-without-review'})
        self.assertTrue(all(count > 0 for count in r['mutants'].values()))


class BridgeCodec(unittest.TestCase):
    def test_rust_and_aiken_evaluation(self):
        r = DRIVER.query('p0-bridge-codec', {})
        self.assertEqual(r['aiken_summary']['total'], 9)
        self.assertEqual(r['aiken_summary']['passed'], 9)
        names = [c['case'] for c in r['cases']]
        self.assertEqual(len(set(names)), 9)
        self.assertEqual(len(names), 9)
        for case in r['cases']:
            self.assertIs(case['rust_accepted'], case['case'].endswith('_roundtrip'))
            self.assertIs(case['aiken_assertion_passed'], True)
            self.assertGreater(case['aiken_execution_units']['cpu'], 0)
            self.assertGreater(case['aiken_execution_units']['mem'], 0)


class SaplingSpike(unittest.TestCase):
    def test_mainnet_proofs_mutations_and_complete_wasm_bundles(self):
        r = DRIVER.query('p0-sapling-spike', {})
        self.assertEqual(r['executor'], 'wasm')
        self.assertEqual(r['rustc'], '1.85.0')
        self.assertEqual(r['target'], 'wasm32-unknown-unknown')
        self.assertIn('--no-default-features', r['build_flags'])
        self.assertEqual(r['imports'], [])
        self.assertGreater(r['wasm_bytes'], 0)
        self.assertRegex(r['wasm_sha256'], r'^[0-9a-f]{64}$')
        vectors = r['vectors']
        self.assertGreaterEqual(len(vectors), 20)
        self.assertEqual(len({v['proof_sha256'] for v in vectors}), len(vectors))
        self.assertEqual([v['index'] for v in vectors], list(range(len(vectors))))
        for vector in vectors:
            self.assertEqual(vector['source_network'], 'zcash-mainnet')
            self.assertRegex(vector['transaction_id'], r'^[0-9a-f]{64}$')
            self.assertIs(vector['accepted'], True)
            self.assertEqual(vector['rejected_bits'], list(range(1536)))
            self.assertEqual(vector['accepted_bits'], [])
        self.assertEqual(r['bundle'], {'spends': 1, 'outputs': 2, 'signatures': 'all', 'decoding': True, 'tree_depth': 32})
        self.assertTrue(r['bundle_transactions'])
        self.assertEqual(len(r['milliseconds']), 20)
        self.assertTrue(all(isinstance(ms, (int,float)) and ms > 0 for ms in r['milliseconds']))
        maximum = max(r['milliseconds'])
        self.assertEqual(r['verdict'], 'GO' if maximum <= 150 else 'GO with caps' if maximum <= 400 else 'fallback A')
        self.assertTrue(r['hardware']['model'])
        mac = r['macbook']
        self.assertEqual(mac['wasm_sha256'], r['wasm_sha256'])
        self.assertEqual(mac['hardware']['arch'], 'arm64')
        self.assertEqual(mac['hardware']['platform'], 'darwin')
        self.assertEqual(mac['engine'], r['engine'])
        self.assertEqual(mac['bundle_transactions'], r['bundle_transactions'])
        self.assertEqual(len(mac['milliseconds']), 20)
        self.assertTrue(all(ms > 0 for ms in mac['milliseconds']))


P0_SUITES = {
    'c-p0-core-no-egress': CoreNoEgress,
    'c-p0-midnight-negative-control': MidnightNegativeControl,
    'c-p0-mainnet-refusal': MainnetRefusal,
    'c-p0-metadata-compat': MetadataCompat,
    'c-p0-bridge-codec': BridgeCodec,
    'c-p0-sapling-spike': SaplingSpike,
}
