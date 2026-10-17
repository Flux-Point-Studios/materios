import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import getpass
import subprocess
import sys
import tempfile

os.environ['NO_COLOR'] = 'true'
ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / 'tools/zk-spec/vendor/metadata-gate/ceremony_metadata_gate.py'
spec = importlib.util.spec_from_file_location('metadata_gate', GATE_PATH)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def run(argv, cwd=ROOT, timeout=3600):
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / '.zk-spec-target'), CARGO_BUILD_JOBS='2', NO_COLOR='true')
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f'{argv[0]} exit {result.returncode}: {result.stderr[-1200:]}')
    return result.stdout


def chain_targets(root):
    command = (root / 'partnerchain/node/src/command.rs').read_text()
    load = command.split('fn load_spec(', 1)[1].split('/// Parse and run', 1)[0]
    aliases = re.findall(r'"([^"\n]*)"\s*(?:\||=>)', load)
    if set(aliases) != {'dev', '', 'local', 'preprod'} or 'ChainSpec::from_json_file(' not in load:
        raise ValueError('unreviewed chain-spec loader route; update source inventory')
    preprod = (root / 'partnerchain/node/src/chain_spec_preprod.rs').read_text()
    ids = re.findall(r'\.with_id\("([^"]+)"\)', preprod)
    if len(ids) != 1:
        raise ValueError('incomplete preprod builder inventory')
    # The production loader has no named mainnet builder. All mainnet specs enter
    # through from_json_file, whose plain and raw forms share the refused route.
    return {'mainnet': [{'route': 'file', 'format': form, 'id': 'materios_mainnet'}
                        for form in ('plain', 'raw')],
            'preprod': [{'route': 'preprod', 'id': ids[0]}],
            'source_sha256': hashlib.sha256(load.encode()).hexdigest(),
            'source': 'partnerchain/node/src/command.rs::load_spec',
            'file_alias_probe': {'route': 'file', 'id': ids[0]}}


def reject_midnight(metadata):
    packages = metadata.get('packages', [])
    if not packages:
        raise ValueError('empty dependency inventory')
    found = sorted({p['name'] for p in packages
                    if any('midnight' in str(p.get(field, '')).lower()
                           for field in ('name', 'source', 'repository'))})
    if found:
        raise ValueError('Midnight dependency: ' + ', '.join(found))
    return sorted({p['name'] for p in packages})


def validate_macbook(record, wasm_sha256):
    if record['wasm_sha256'] != wasm_sha256:
        raise ValueError('MacBook capture belongs to a different Wasm artifact')
    if record['hardware']['arch'] != 'arm64' or record['hardware']['platform'] != 'darwin':
        raise ValueError('MacBook capture has the wrong architecture')
    if len(record['milliseconds']) != 20 or not all(isinstance(ms, (int, float)) and ms > 0 for ms in record['milliseconds']):
        raise ValueError('MacBook capture needs twenty positive bundle samples')
    if len(record['vectors']) < 20 or not all(v['accepted'] is True for v in record['vectors']):
        raise ValueError('MacBook mainnet proofs did not verify')
    if record['bundle'] != {'spends': 1, 'outputs': 2, 'signatures': 'all', 'decoding': True, 'tree_depth': 32}:
        raise ValueError('MacBook benchmark is not a complete bundle')


def macbook_observation(root):
    record = json.loads((root/'docs/native-zk-evidence/p0-macbook.json').read_text())
    wasm = root/'.zk-spec-target/wasm32-unknown-unknown/release/materios_zk_wasm.wasm'
    validate_macbook(record, hashlib.sha256(wasm.read_bytes()).hexdigest())
    return record


def metadata_mutations(root):
    metadata = json.loads((root / 'tools/zk-spec/fixtures/launch-metadata.json').read_text())['V14']
    old = gate.reduced_from_v14(metadata)
    results = {}
    for name, category in [('insert-error-in-middle', 'errors'), ('insert-event-in-middle', 'events')]:
        new = copy.deepcopy(old)
        pallet = next(p for p in new['pallets'].values() if p[category])
        for variant in pallet[category].values():
            variant['index'] += 1
        results[name] = len(gate.assert_matches_expectation(gate.compute_diff(old, new), {}))
    new = copy.deepcopy(old)
    pallets = list(new['pallets'].values())
    pallets[1]['index'] = pallets[0]['index']
    results['reuse-pallet-index'] = len(gate.assert_matches_expectation(gate.compute_diff(old, new), {}))
    new = copy.deepcopy(old)
    new['signed_extensions'].reverse()
    results['change-signed-extra'] = len(gate.assert_matches_expectation(gate.compute_diff(old, new), {}))
    results['stale-manifest'] = len(gate.assert_matches_expectation(gate.compute_diff(old, old), {'pallets_removed': {'Balances': 99}}))
    new = copy.deepcopy(old)
    key = 'SessionCommitteeManagement.MaxValidators'
    prior = int.from_bytes(bytes.fromhex(new['pallets']['SessionCommitteeManagement']['constants']['MaxValidators']), 'little')
    new['pallets']['SessionCommitteeManagement']['constants']['MaxValidators'] = (prior-1).to_bytes(4,'little').hex()
    results['shrink-bound-without-review'] = len(gate.check_bound_shrink(old, new, {'canaries': {key: prior-1}}))
    return results


def metadata_compat(root):
    baseline = json.loads((root / 'tools/zk-spec/fixtures/launch-baseline.json').read_text())
    for path, expected in baseline['source_files'].items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
            raise ValueError('launch source changed: ' + path)
    path = root / baseline['metadata_path']
    if hashlib.sha256(path.read_bytes()).hexdigest() != baseline['metadata_sha256']:
        raise ValueError('launch metadata baseline hash changed')
    wasm = root / 'tools/zk-spec/artifacts/runtime.wasm'
    if not wasm.is_file():
        raise ValueError('rebuilt runtime artifact missing')
    subwasm = root / 'tools/zk-spec/artifacts/subwasm/usr/bin/subwasm'
    old = gate.reduced_from_v14(json.loads(path.read_text())['V14'])
    new = gate.extract_reduced(str(wasm), str(subwasm))
    failures = gate.assert_matches_expectation(gate.compute_diff(old, new), {})
    version = gate.extract_runtime_version(str(wasm), str(subwasm))
    if version['transactionVersion'] != baseline['transaction_version']:
        failures.append('transaction version changed')
    return {'baseline_identity': baseline['identity'], 'baseline_metadata_sha256': baseline['metadata_sha256'],
            'runtime_sha256': hashlib.sha256(wasm.read_bytes()).hexdigest(), 'executor': 'subwasm-0.21.3',
            'old_pallets': len(old['pallets']), 'new_pallets': len(new['pallets']),
            'gate_exit': int(bool(failures)), 'violations': failures, 'mutants': metadata_mutations(root),
            'source_files_checked': len(baseline['source_files']), 'runtime_version': version}


def core_no_egress(root):
    metadata = json.loads(run(['cargo', '+1.85.0', 'metadata', '--locked', '--offline', '--format-version', '1',
                               '--manifest-path', 'tools/zk-spec/core/Cargo.toml']))
    packages = reject_midnight(metadata)
    host = os.stat('/proc/self/ns/net').st_ino
    command = ['unshare', '--net'] if os.geteuid() == 0 else ['sudo', '-n', 'unshare', '--net', 'runuser', '-u', getpass.getuser(), '--']
    result = json.loads(run(command + [sys.executable, 'tools/zk-spec/p0_tools.py', 'netns-child']))
    if result['test_netns_inode'] == host:
        raise ValueError('no namespace isolation')
    result.update(host_netns_inode=host, packages=packages)
    return result


def netns_child():
    routes = Path('/proc/net/route').read_text().splitlines()[1:]
    if routes:
        raise ValueError('network namespace has routes')
    probes = {}
    for name, host in [('srs.midnight.network','srs.midnight.network'), ('node.midnight.network','node.midnight.network'), ('direct-ip','1.1.1.1')]:
        try:
            with socket.create_connection((host,443),timeout=2):
                probes[name] = 0
        except OSError as error:
            probes[name] = error.errno or -1
    if any(code == 0 for code in probes.values()):
        raise ValueError('egress probe succeeded')
    cargo = shutil.which('cargo') or str(Path.home()/'.cargo/bin/cargo')
    base = ['nice','-n','10',cargo,'+1.85.0']
    with tempfile.TemporaryDirectory(prefix='no-egress-', dir=ROOT/'.zk-spec-target') as target:
        flags = ['--offline','--locked','--no-default-features','--target-dir',target,
                 '--manifest-path','tools/zk-spec/core/Cargo.toml']
        output = run(base + ['build','--message-format=json'] + flags)
        artifacts = [json.loads(line) for line in output.splitlines()]
        compiled = sorted({a['package_id'] for a in artifacts
                           if a.get('reason') == 'compiler-artifact' and a.get('fresh') is False
                           and any(Path(file).is_file() for file in a['filenames'])})
        if not any('materios-zk-core' in package for package in compiled):
            raise ValueError('core was not freshly compiled inside the denied-network namespace')
        output = run(base + ['test'] + flags)
    summaries = re.findall(r'test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;', output)
    if not summaries or sum(int(n) for n,_ in summaries) < 3 or any(int(ignored) for _,ignored in summaries):
        raise ValueError('core suite empty or ignored')
    return {'test_netns_inode': os.stat('/proc/self/ns/net').st_ino, 'external_routes': routes,
            'denied_probes': probes, 'tests_passed': sum(int(n) for n,_ in summaries),
            'compiled_packages': compiled,
            'build_exit': 0, 'test_exit': 0, 'midnight_dependencies': []}


def negative_control(root):
    with tempfile.TemporaryDirectory(prefix='midnight-negative-', dir=root/'.zk-spec-scratch') as directory:
        directory = Path(directory)
        shutil.copytree(root/'tools/zk-spec/core', directory/'core')
        manifest = (directory/'core/Cargo.toml').read_text().replace('edition.workspace = true','edition = "2021"').replace('rust-version.workspace = true','rust-version = "1.85"').replace('license.workspace = true','license = "MIT OR Apache-2.0"')
        manifest = manifest.replace('[dependencies]', '[dependencies]\nmidnight-negative-control = { path = "../midnight" }')
        (directory/'core/Cargo.toml').write_text(manifest)
        (directory/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["core","midnight"]\n[patch.crates-io]\ncore2={path='+json.dumps(str(root/'tools/zk-spec/vendor/core2'))+'}\n')
        (directory/'Cargo.lock').write_bytes((root/'tools/zk-spec/Cargo.lock').read_bytes())
        (directory/'midnight/src').mkdir(parents=True)
        (directory/'midnight/Cargo.toml').write_text('[package]\nname="midnight-negative-control"\nversion="0.0.0"\nedition="2021"\n')
        (directory/'midnight/src/lib.rs').write_text('#![no_std]\n')
        metadata = json.loads(run(['cargo','+1.85.0','metadata','--offline','--format-version','1','--manifest-path',str(directory/'core/Cargo.toml')]))
        try:
            reject_midnight(metadata)
        except ValueError as error:
            if str(error) != 'Midnight dependency: midnight-negative-control':
                raise
            return {'injected': 'midnight-negative-control', 'gate_exit': 1, 'reason': str(error)}
        raise ValueError('injected Midnight dependency escaped exclusion gate')


def refusal_mutants(root):
    source = (root / 'tools/zk-spec/core/src/activation.rs').read_text()
    mutants = {
        'allow-file-mainnet': source.replace('_ => Err(MainnetDenied)', '_ => Ok(())'),
        'id-only-preprod-alias': source.replace('("preprod", "materios_preprod_v6")', '(_, "materios_preprod_v6")'),
    }
    results = {}
    with tempfile.TemporaryDirectory(prefix='refusal-mutants-', dir=root/'.zk-spec-scratch') as directory:
        directory = Path(directory)
        for name, mutated in mutants.items():
            if source == mutated:
                raise ValueError('refusal mutation did not change source')
            test = mutated + '\n#[test] fn mainnet_denied() { assert!(enable("file", "materios_mainnet").is_err()); }\n#[test] fn renamed_mainnet_denied() { assert!(enable("file", "materios_preprod_v6").is_err()); }\n'
            (directory/'mutant.rs').write_text(test)
            run(['nice','-n','10','rustc','+1.85.0','--test',str(directory/'mutant.rs'),'-o',str(directory/'mutant')])
            result = subprocess.run([str(directory/'mutant')],capture_output=True,text=True,check=False)
            if result.returncode == 0 or 'test result: FAILED.' not in result.stdout:
                raise ValueError('refusal mutant escaped or failed for an unrelated reason')
            results[name] = {'test_exit':result.returncode,'failed_assertions':result.stdout.count('assertion failed:')}
    return results


if __name__ == '__main__':
    operations = {'macbook-observation': lambda: macbook_observation(ROOT), 'refusal-mutants': lambda: refusal_mutants(ROOT), 'chain-targets': lambda: chain_targets(ROOT), 'metadata-compat': lambda: metadata_compat(ROOT),
                  'core-no-egress': lambda: core_no_egress(ROOT), 'netns-child': netns_child,
                  'midnight-negative-control': lambda: negative_control(ROOT)}
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in operations:
            raise ValueError('unknown P0 operation')
        print(json.dumps(operations[sys.argv[1]]()))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
