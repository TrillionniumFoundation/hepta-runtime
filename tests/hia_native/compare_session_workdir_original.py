"""Build and run the unchanged original on the devserver/CI, retaining all bytes."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/hia_native'))
from session_workdir_original import oracle_source

sha = lambda raw: hashlib.sha256(raw).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False, mode=0o700)
    corpus = args.corpus.resolve(strict=True)
    source = oracle_source(args.runtime.resolve(strict=True)).encode()
    native_path = corpus / 'result.json'; native_hash = sha(native_path.read_bytes())
    native = json.loads(native_path.read_bytes())
    assert native['schema'] == 'hepta.runtime.session-workdir-native-tests.v1' and native['status'] == 'PASS'
    files = [Path(__file__), ROOT / 'tests/hia_native/session_workdir_original.py', args.runtime / 'src/mcp/server.rs', native_path]
    pins = {str(p): sha(p.read_bytes()) for p in files}
    raw = {}
    for name in ['input.bin.gz', 'native-output.bin.gz']:
        value = (corpus / name).read_bytes(); expected = native['streams'][name]
        assert len(value) == expected['gzip_bytes'] and sha(value) == expected['gzip_sha256']
        raw[name] = gzip.decompress(value)
        assert len(raw[name]) == expected['raw_bytes'] and sha(raw[name]) == expected['raw_sha256']
    (out / 'original.rs').write_bytes(source)
    records = []
    env = {k: v for k, v in os.environ.items() if not k.startswith('HIA_')}
    def run(name, command, input_bytes=None, compressed=False):
        started = time.monotonic()
        done = subprocess.run(list(map(str, command)), input=input_bytes, capture_output=True, timeout=180, env=env)
        (out / (name + ('.stdout.gz' if compressed else '.stdout'))).write_bytes(
            gzip.compress(done.stdout, mtime=0) if compressed else done.stdout)
        (out / (name + '.stderr')).write_bytes(done.stderr)
        record = {'name': name, 'command': list(map(str, command)), 'exit_code': done.returncode,
            'timeout_seconds': 180, 'elapsed_seconds': time.monotonic() - started,
            'stdout_bytes': len(done.stdout), 'stderr_bytes': len(done.stderr),
            'stdout_sha256': sha(done.stdout), 'stderr_sha256': sha(done.stderr)}
        records.append(record)
        (out / 'processes.json').write_text(json.dumps(records, indent=2, sort_keys=True) + '\n')
        assert done.returncode == 0, (name, done.returncode, done.stderr[-4096:])
        return done
    version = run('rust-version', [args.rustc, '--version'])
    run('build', [args.rustc, '--edition=2024', '-O', out / 'original.rs', '-o', out / 'original'])
    binary_hash = sha((out / 'original').read_bytes())
    replay = run('replay', [out / 'original'], raw['input.bin.gz'], compressed=True)
    assert replay.stdout == raw['native-output.bin.gz']
    completed = json.loads(replay.stderr)
    assert completed == {'status': 'PASS', 'rows': native['counts']['reference_rows'], 'sessions': 9, 'actual_poison_events': 9}
    latch = run('latch', [out / 'original', '--latch-test'])
    assert json.loads(latch.stdout) == {'status': 'PASS', 'actual_threads': 64, 'first': 1, 'later': 63}
    assert not latch.stderr
    assert all(sha(Path(name).read_bytes()) == value for name, value in pins.items())
    assert sha((out / 'original').read_bytes()) == binary_hash and oracle_source(args.runtime).encode() == source
    result = {'schema': 'hepta.runtime.session-workdir-original.v1', 'status': 'PASS',
        'native_result_sha256': native_hash, 'original_source_sha256': sha(source),
        'original_executable_sha256': binary_hash, 'inputs': pins, 'processes': records,
        'original_rows': completed['rows'], 'actual_sessions': 9, 'actual_poison_events': 9,
        'actual_latch_threads': 64, 'complete_output_bytes': len(replay.stdout),
        'complete_output_sha256': sha(replay.stdout), 'source_unchanged': True,
        'public_workdir_handler_complete': False, 'production_activated': False,
        'whole_runtime_replaced': False, 'old_stack_removal_qualified': False}
    (out / 'report.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['inputs', 'processes']}, sort_keys=True))

if __name__ == '__main__': main()
