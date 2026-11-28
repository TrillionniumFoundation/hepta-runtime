"""Meaningful tamper controls for complete file-lock artifacts and executions."""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / 'scripts') not in sys.path:
    sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_file_lock_build import inspect_bundle, file_record, read, obj, sha
from hia_native_file_lock_qualification import native_evidence, state_evidence, key_evidence, pins

def altered(raw):
    data = bytearray(raw)
    assert data
    data[-1] ^= 1
    return bytes(data)

def run(bundle, state, key, state_stdout, key_stdout, output):
    bundle, state, key = (Path(p).resolve(strict=True) for p in (bundle, state, key))
    output = Path(output).resolve()
    output.mkdir(mode=0o700)
    before = pins(ROOT)
    started = time.monotonic()
    good = native_evidence(bundle, state, key, source_root=ROOT,
        state_stdout=state_stdout, key_stdout=key_stdout)
    (output / 'accepted-native-evidence.json').write_text(json.dumps(good, sort_keys=True, indent=2) + '\n')
    record = {'schema': 'hepta.runtime.file-lock-evidence-controls.v1', 'status': 'RUNNING', 'groups': 3,
        'source_files': before, 'accepted_native_evidence': file_record(output / 'accepted-native-evidence.json'),
        'actual_native_calls': 0, 'actual_original_calls': 0, 'refusals': []}
    scratch = output / 'owned-mutation-fixture'
    scratch.mkdir(mode=0o700)
    copied_bundle = scratch / 'bundle'
    shutil.copytree(bundle.parent, copied_bundle)
    copied_state, copied_key = scratch / 'state', scratch / 'key'
    shutil.copytree(state, copied_state)
    shutil.copytree(key, copied_key)
    snapshot = inspect_bundle(copied_bundle / 'manifest.json', source_root=ROOT)
    # The copied manifests and bytes have the same identities; no semantic run
    # is claimed for any private mutation fixture.
    assert snapshot == good['artifacts']

    def refuse(name, action, check, paths):
        saved = [(path, path.read_bytes(), path.stat().st_mode & 0o777) for path in paths]
        try:
            action()
            try:
                check()
            except (ValueError, OSError, AssertionError, KeyError, EOFError, UnicodeError) as error:
                record['refusals'].append({'name': name, 'reason': type(error).__name__, 'message': str(error)})
            else:
                raise AssertionError('changed evidence accepted: ' + name)
        finally:
            for path, raw, mode in saved:
                path.chmod(0o600)
                path.write_bytes(raw)
                path.chmod(mode)

    def bytes_change(path):
        path.chmod(0o600)
        path.write_bytes(altered(path.read_bytes()))

    def object_change(path, update):
        value = obj(path)
        update(value)
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

    try:
        check_bundle = lambda: inspect_bundle(copied_bundle / 'manifest.json', source_root=ROOT)
        for name in ('state.image.bin', 'key.image.bin', 'state-packer.image.bin', 'key-packer.image.bin',
            'file-lock-state.elf', 'file-lock-key.elf', 'state-build/module.output.bin',
            'key-build/module.stdout.log', 'state-pack/pack.input.bin', 'key-pack/pack.output.bin',
            'state-pack/pack.stdout.log', 'key-pack/pack.receipt.json'):
            path = copied_bundle / name
            refuse('artifact-' + name.replace('/', '-'), lambda p=path: bytes_change(p), check_bundle, [path])
        manifest = copied_bundle / 'manifest.json'
        refuse('false-production-activation', lambda: object_change(manifest, lambda v: v.update(production_activated=True)), check_bundle, [manifest])
        path = copied_bundle / 'key.json'
        refuse('wrong-compiler-commit', lambda: object_change(path, lambda v: v.update(compiler_commit='0' * 40)), check_bundle, [path])
        path = copied_state / 'requests.bin.gz'
        refuse('complete-state-input-corrupt', lambda: bytes_change(path), lambda: state_evidence(copied_state, snapshot, source_root=ROOT), [path])
        path = copied_state / 'native-output.bin.gz'
        refuse('complete-state-output-corrupt', lambda: bytes_change(path), lambda: state_evidence(copied_state, snapshot, source_root=ROOT), [path])
        path = copied_state / 'elf.stdout'
        refuse('actual-state-elf-output-corrupt', lambda: bytes_change(path), lambda: state_evidence(copied_state, snapshot, source_root=ROOT), [path])
        path = copied_state / 'growth.json'
        refuse('missing-growth-refusal', lambda: path.write_text('[]\n'), lambda: state_evidence(copied_state, snapshot, source_root=ROOT), [path])
        path = copied_key / 'bulk/requests.bin'
        refuse('complete-key-input-corrupt', lambda: bytes_change(path), lambda: key_evidence(copied_key, snapshot, source_root=ROOT), [path])
        path = copied_key / 'bulk/native.stdout'
        refuse('actual-key-output-corrupt', lambda: bytes_change(path), lambda: key_evidence(copied_key, snapshot, source_root=ROOT), [path])
        path = copied_key / 'result.json'
        refuse('omitted-key-admission', lambda: object_change(path, lambda v: v['admission'].pop()),
            lambda: key_evidence(copied_key, snapshot, source_root=ROOT), [path])
        refuse('omitted-dirty-return-control', lambda: object_change(path, lambda v: v['transport'].pop()),
            lambda: key_evidence(copied_key, snapshot, source_root=ROOT), [path])
        refuse('stale-native-key-source', lambda: object_change(path, lambda v: v['source_files']['tests/hia_native/test_file_lock_key.py'].update(sha256='0' * 64)),
            lambda: key_evidence(copied_key, snapshot, source_root=ROOT), [path])
        fake = scratch / 'fake-completion.json'
        fake.write_bytes(b'{"status":"PASS"}\n')
        refuse('fabricated-native-completion', lambda: None, lambda: native_evidence(bundle, state, key,
            source_root=ROOT, state_stdout=state_stdout, key_stdout=fake), [])
        refuse('missing-native-completion', lambda: None, lambda: native_evidence(bundle, state, key,
            source_root=ROOT, state_stdout=state_stdout, key_stdout=None), [])
        assert len(record['refusals']) == 25
        assert native_evidence(bundle, state, key, source_root=ROOT,
            state_stdout=state_stdout, key_stdout=key_stdout) == good
        assert pins(ROOT) == before
        record['status'] = 'PASS'
    except BaseException as error:
        record.update(status='FAIL', failure=repr(error))
        raise
    finally:
        record['elapsed'] = time.monotonic() - started
        (output / 'result.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    # Only restored private copies created in this invocation are removed.
    # The original sources, bundle and complete execution artifacts survive.
    shutil.rmtree(scratch)
    print(json.dumps(record, sort_keys=True))
    return record

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=os.environ.get('HIA_FILE_LOCK_MANIFEST'))
    parser.add_argument('--state-corpus', type=Path, required=True)
    parser.add_argument('--key-corpus', type=Path, required=True)
    parser.add_argument('--state-stdout', type=Path, required=True)
    parser.add_argument('--key-stdout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.bundle is None:
        parser.error('the actual native bundle is required')
    run(args.bundle, args.state_corpus, args.key_corpus, args.state_stdout, args.key_stdout, args.output)
