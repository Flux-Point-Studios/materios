import unittest
from pathlib import Path
import shutil
import tempfile
import vectors


class VectorTests(unittest.TestCase):
    def test_mainnet_corpus_contains_twenty_proofs_and_full_bundle(self):
        bundles = vectors.load(Path(__file__).parent / 'fixtures')
        self.assertGreaterEqual(sum(len(b['spends']) + len(b['outputs']) for b in bundles), 20)
        self.assertTrue(any(len(b['spends']) == 1 and len(b['outputs']) == 2 for b in bundles))
        self.assertTrue(all(len(bytes.fromhex(b['sighash'])) == 32 for b in bundles))

    def test_truncated_block_fails(self):
        with self.assertRaises(ValueError):
            vectors.parse_block(b'\x00' * 80, 0x76b809bb)

    def test_noncanonical_compact_size_fails(self):
        with self.assertRaises(ValueError):
            vectors.Reader(bytes.fromhex('fdfc00')).compact()

    def test_generated_corpus_cannot_diverge_from_public_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixtures'
            shutil.copytree(Path(__file__).parent / 'fixtures', path)
            vectors.verify(path)
            data = bytearray((path / 'actions.bin').read_bytes())
            data[140] ^= 1
            (path / 'actions.bin').write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'derived corpus differs'):
                vectors.verify(path)


if __name__ == '__main__':
    unittest.main()
