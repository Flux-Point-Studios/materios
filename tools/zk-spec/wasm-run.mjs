import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {cpus, arch, platform, release} from 'node:os';
import {performance} from 'node:perf_hooks';

const wasm = readFileSync(process.argv[2]);
const mode = process.argv[3];
if (![undefined, '--bench-only', '--verify-only'].includes(mode)) throw new Error('unknown execution mode');
const module = await WebAssembly.compile(wasm);
const imports = WebAssembly.Module.imports(module);
if (imports.length) throw new Error('no_std spike must have zero host imports');
const {exports: zk} = await WebAssembly.instantiate(module, {});
if (zk.zk_init() !== 1) throw new Error('Sapling verification key decoding failed');
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/bundles.json', import.meta.url)));
const vectors = [];
let index = 0;
for (const bundle of fixtures) {
  for (const [key, offset] of [['spends', 128], ['outputs', 756]]) {
    for (const action of bundle[key]) {
      const proof = Buffer.from(action, 'hex').subarray(offset, offset + 192);
      const accepted = zk.zk_vector(index, -1) === 1;
      if (!accepted) throw new Error(`mainnet proof rejected at index ${index}, ${bundle.transaction_id}`);
      const rejectedBits = [], acceptedBits = [];
      if (mode !== '--bench-only') {
        for (let bit = 0; bit < 1536; bit++) {
          (zk.zk_vector(index, bit) === 0 ? rejectedBits : acceptedBits).push(bit);
        }
      }
      if (acceptedBits.length) throw new Error(`single-bit mutation accepted for vector ${index}: ${acceptedBits}`);
      vectors.push({index, proof_sha256: createHash('sha256').update(proof).digest('hex'),
        transaction_id: bundle.transaction_id, source_file: bundle.source_file,
        source_network: bundle.source_network, accepted, rejected_bits: rejectedBits, accepted_bits: acceptedBits});
      index++;
    }
  }
}
const full = fixtures.filter(b => b.spends.length === 1 && b.outputs.length === 2);
if (full.length === 0) throw new Error('no complete bundles');
for (let i = 0; i < full.length; i++) {
  if (zk.zk_bundle(i, 0) !== 1) throw new Error(`complete bundle rejected: ${full[i].transaction_id}`);
  for (const mutation of [1,2,3]) {
    if (zk.zk_bundle(i, mutation) !== 0) throw new Error(`bundle mutation accepted: ${i}/${mutation}`);
  }
}
const milliseconds = [];
for (let sample = 0; sample < (mode === '--verify-only' ? 0 : 20); sample++) {
  const i = sample % full.length;
  const start = performance.now();
  if (zk.zk_bundle(i, 0) !== 1) throw new Error('measured bundle failed');
  milliseconds.push(performance.now() - start);
}
const max = Math.max(...milliseconds);
if (vectors.length < 20) throw new Error('fewer than twenty mainnet proofs executed');
console.log(JSON.stringify({executor: 'wasm', engine: {node: process.version, v8: process.versions.v8},
  hardware: {arch: arch(), platform: platform(), release: release(), model: cpus()[0].model, logical_cpus: cpus().length},
  wasm_sha256: createHash('sha256').update(wasm).digest('hex'), wasm_bytes: wasm.length, imports,
  vectors, bundle: {spends: 1, outputs: 2, signatures: 'all', decoding: true, tree_depth: 32},
  bundle_transactions: full.map(b => b.transaction_id), milliseconds,
  verdict: milliseconds.length === 0 ? 'not measured' : max <= 150 ? 'GO' : max <= 400 ? 'GO with caps' : 'fallback A',
  bundle_cap: milliseconds.length === 0 ? null : Math.max(1, Math.floor(750 / max)), measured_at: new Date().toISOString()}));
