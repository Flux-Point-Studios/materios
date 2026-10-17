"""Public Zebra v4 blocks and ZIP-243 shielded signature digests."""
import hashlib
import json
import struct
import sys
from pathlib import Path


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        value = self.data[self.pos:self.pos + count]
        if len(value) != count:
            raise ValueError('truncated Zcash encoding')
        self.pos += count
        return value

    def compact(self):
        tag = self.take(1)[0]
        if tag < 253:
            return tag
        value = int.from_bytes(self.take({253: 2, 254: 4, 255: 8}[tag]), 'little')
        if value < {253: 253, 254: 65536, 255: 4294967296}[tag]:
            raise ValueError('noncanonical compact size')
        return value


def digest(person, data):
    return hashlib.blake2b(data, digest_size=32, person=person).digest()


def parse_block(raw, branch):
    r = Reader(raw)
    r.take(140)
    r.take(r.compact())
    bundles = []
    for _ in range(r.compact()):
        start = r.pos
        header = r.take(8)
        if header != bytes.fromhex('0400008085202f89'):
            raise ValueError('corpus requires Sapling v4 transactions')
        prevouts, sequences, txouts = b'', b'', b''
        for _ in range(r.compact()):
            prevouts += r.take(36)
            r.take(r.compact())
            sequences += r.take(4)
        for _ in range(r.compact()):
            output_start = r.pos
            r.take(8)
            r.take(r.compact())
            txouts += r.data[output_start:r.pos]
        lock_expiry = r.take(8)
        balance = r.take(8)
        spends = [r.take(384) for _ in range(r.compact())]
        outputs = [r.take(948) for _ in range(r.compact())]
        joinsplits = [r.take(1698) for _ in range(r.compact())]
        jspub = r.take(32) if joinsplits else b''
        if joinsplits:
            r.take(64)
        binding = r.take(64) if spends or outputs else b''
        tx = r.data[start:r.pos]
        if not binding:
            continue
        zero = bytes(32)
        message = (header + digest(b'ZcashPrevoutHash', prevouts)
                   + digest(b'ZcashSequencHash', sequences) + digest(b'ZcashOutputsHash', txouts)
                   + (digest(b'ZcashJSplitsHash', b''.join(joinsplits) + jspub) if joinsplits else zero)
                   + (digest(b'ZcashSSpendsHash', b''.join(s[:320] for s in spends)) if spends else zero)
                   + (digest(b'ZcashSOutputHash', b''.join(outputs)) if outputs else zero)
                   + lock_expiry + balance + struct.pack('<I', 1))
        sighash = digest(b'ZcashSigHash' + struct.pack('<I', branch), message)
        bundles.append({'transaction_id': hashlib.sha256(hashlib.sha256(tx).digest()).digest()[::-1].hex(),
                        'transaction_hex': tx.hex(), 'sighash': sighash.hex(),
                        'value_balance': int.from_bytes(balance, 'little', signed=True),
                        'spends': [s.hex() for s in spends], 'outputs': [o.hex() for o in outputs],
                        'binding_sig': binding.hex()})
    if r.pos != len(raw):
        raise ValueError('trailing block bytes')
    return bundles


def load(fixtures):
    bundles = []
    for source in json.loads((fixtures / 'provenance.json').read_text()):
        if not source['file'].startswith('block-main-'):
            continue
        data = (fixtures / source['file']).read_bytes()
        if hashlib.sha256(data).hexdigest() != source['sha256']:
            raise ValueError('public fixture hash mismatch')
        height = int(source['file'][11:-4].replace('-', ''))
        branch = 0x76b809bb if height < 653600 else 0x2bb40e60 if height < 903000 else 0xf5b9230b
        for bundle in parse_block(bytes.fromhex(data.decode()), branch):
            bundles.append(dict(bundle, source_file=source['file'], source_network='zcash-mainnet', height=height))
    return bundles


def generated(fixtures):
    bundles = load(fixtures)
    actions = b''.join(bytes([kind]) + bytes.fromhex(action)
                       for b in bundles for kind, key in [(1, 'spends'), (0, 'outputs')]
                       for action in b[key])
    encoded = []
    for b in bundles:
        if len(b['spends']) != 1 or len(b['outputs']) != 2:
            continue
        raw = bytes.fromhex(b['sighash']) + struct.pack('<q', b['value_balance'])
        for key in ('spends', 'outputs'):
            raw += struct.pack('<I', len(b[key])) + b''.join(bytes.fromhex(a) for a in b[key])
        raw += bytes.fromhex(b['binding_sig'])
        encoded.append(struct.pack('<I', len(raw)) + raw)
    return {'actions.bin': actions, 'bundles.bin': b''.join(encoded),
            'bundles.json': (json.dumps(bundles, indent=2) + '\n').encode()}


def verify(fixtures):
    for source in json.loads((fixtures / 'provenance.json').read_text()):
        if hashlib.sha256((fixtures / source['file']).read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('public fixture hash mismatch: ' + source['file'])
    for name, data in generated(fixtures).items():
        if (fixtures / name).read_bytes() != data:
            raise ValueError('derived corpus differs from public blocks: ' + name)


if __name__ == '__main__':
    fixtures = Path(__file__).parent / 'fixtures'
    if sys.argv[1:] == ['--check']:
        verify(fixtures)
        print('public provenance and all derived corpus bytes verified')
    elif sys.argv[1:]:
        raise SystemExit('usage: vectors.py [--check]')
    else:
        for name, data in generated(fixtures).items():
            (fixtures / name).write_bytes(data)
        print('regenerated public corpus')
