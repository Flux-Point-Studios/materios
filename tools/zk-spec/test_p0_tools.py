import unittest
from pathlib import Path
import p0_tools

ROOT = Path(__file__).resolve().parents[2]


class P0ToolTests(unittest.TestCase):
    def test_mainnet_inventory_includes_file_routes_and_preprod_control(self):
        inventory = p0_tools.chain_targets(ROOT)
        self.assertTrue(inventory['mainnet'])
        self.assertEqual({x['format'] for x in inventory['mainnet']}, {'plain', 'raw'})
        self.assertIn('materios_preprod_v6', [x['id'] for x in inventory['preprod']])

    def test_midnight_name_in_transitive_graph_is_refused(self):
        metadata = {'packages': [{'name': 'core'}, {'name': 'midnight-negative-control'}]}
        with self.assertRaisesRegex(ValueError, 'Midnight dependency'):
            p0_tools.reject_midnight(metadata)

    def test_empty_dependency_inventory_is_refused(self):
        with self.assertRaises(ValueError):
            p0_tools.reject_midnight({'packages': []})

    def test_midnight_source_cannot_hide_behind_generic_package_name(self):
        metadata = {'packages': [{'name': 'ledger', 'source': 'git+https://github.com/midnightntwrk/ledger'}]}
        with self.assertRaisesRegex(ValueError, 'Midnight dependency'):
            p0_tools.reject_midnight(metadata)

    def test_metadata_mutants_are_detected_by_existing_gate(self):
        result = p0_tools.metadata_mutations(ROOT)
        self.assertEqual(set(result), {'insert-error-in-middle', 'insert-event-in-middle',
            'reuse-pallet-index', 'change-signed-extra', 'stale-manifest', 'shrink-bound-without-review'})
        self.assertTrue(all(x > 0 for x in result.values()))


if __name__ == '__main__':
    unittest.main()
