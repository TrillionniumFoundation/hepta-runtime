# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual retained-admission refusals; executes no native or Rust owner."""
from __future__ import annotations
import argparse
import contextlib
import copy
import gzip
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for location in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(location) not in sys.path: sys.path.insert(0, str(location))
import compare_batch_write_wide_retained as retained
import hia_native_batch_write_qualification as q
from hia_native_batch_write_build import exact, read, obj, sha, file_record

CONTROLS = ('wrong-invocation', 'wrong-admission-digest', 'wrong-source-rehashed', 'wrong-elf-rehashed',
    'wrong-context-run-rehashed', 'failed-native-check-rehashed', 'missing-gzip', 'damaged-gzip',
    'truncated-gzip', 'valid-gzip-suffix-all-envelopes-rehashed', 'unknown-fixture-member',
    'symlink-fixture-target', 'foreign-fixture-path')


def run(root, manifest, corpus, stdout_dir, admission, invocation, output):
    root, manifest, corpus, stdout_dir, admission = map(lambda p: Path(p).resolve(strict=True),
        (root, manifest, corpus, stdout_dir, admission))
    output = Path(output).absolute(); output.mkdir(mode=0o700); started = time.monotonic()
    original = obj(admission); expected_sha = sha(read(admission))
    before = retained.admit_native(admission, expected_sha, invocation, root, manifest, corpus, stdout_dir)
    shadow = output / 'shadow'; shadow.mkdir()
    manifest_relative = Path(original['manifest_relative']); target_manifest = shadow / manifest_relative
    target_manifest.parent.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(manifest.parent, target_manifest.parent)
    for name in retained.CAPTURES:
        target = shadow / 'batch-write/wide' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(corpus / 'wide' / name, target)
    for name in (retained.NATIVE_NAME + '.stdout', retained.NATIVE_NAME + '.stderr', retained.ADMISSION):
        shutil.copyfile(stdout_dir / name, shadow / name)
    context = original['context']
    names = ('original-native.json', 'original-native-report.json') if context['mode'] == 'ci-original-pipeline' else (context['phase_file'],)
    for name in names: shutil.copyfile(stdout_dir / name, shadow / name)
    descriptor = shadow / retained.ADMISSION; rows = []

    @contextlib.contextmanager
    def changes():
        saved = {}; touched = {}
        def change(path, value):
            path = Path(path)
            if path not in saved: saved[path] = read(path) if path.exists() else None
            if value is None:
                path.unlink()
            else:
                if not isinstance(value, bytes): value = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
                path.write_bytes(value)
            touched[str(path.relative_to(output))] = None if value is None else dict(bytes=len(value), sha256=sha(value))
        try: yield change, touched
        finally:
            for path, value in saved.items():
                if value is None:
                    if path.exists(): path.unlink()
                else: path.write_bytes(value)

    def inspect(digest=None, selected_invocation=None):
        return retained.admit_native(descriptor, digest or sha(read(descriptor)), selected_invocation or invocation,
            root, target_manifest, shadow / 'batch-write', shadow)

    def reject(name, action, mutations=None):
        try: action()
        except (ValueError, OSError, EOFError, KeyError) as error:
            rows.append(dict(name=name, status='REJECTED', error=type(error).__name__ + ': ' + str(error),
                             mutations=dict(mutations or {})))
        else: raise AssertionError('damaged retained native wide evidence was accepted: ' + name)

    reject('wrong-invocation', lambda: inspect(selected_invocation=invocation + '-old'))
    reject('wrong-admission-digest', lambda: inspect(digest='00' * 32))
    for name, mutate in (
        ('wrong-source-rehashed', lambda d: d['source_files']['native/batch_write.hepta'].update(sha256='00' * 32)),
        ('wrong-elf-rehashed', lambda d: d.update(native_binary_sha256='00' * 32)),
        ('wrong-context-run-rehashed', lambda d: d['context'].update(invocation=invocation + '-old')),
        ('failed-native-check-rehashed', lambda d: d['native_process'].update(exit_code=1)),
    ):
        with changes() as (change, touched):
            damaged = copy.deepcopy(original); mutate(damaged); change(descriptor, damaged)
            reject(name, inspect, touched)
    capture = shadow / 'batch-write/wide/native/normalized.bin.gz'
    for name, mutate in (
        ('missing-gzip', lambda b: None),
        ('damaged-gzip', lambda b: b[:len(b)//2] + bytes([b[len(b)//2] ^ 1]) + b[len(b)//2+1:]),
        ('truncated-gzip', lambda b: b[:-1]),
    ):
        with changes() as (change, touched):
            change(capture, mutate(read(capture))); reject(name, inspect, touched)
    # Deliberately update every enclosing digest, stdout summary and actual
    # phase/snapshot envelope. The fixed complete output domain must still
    # refuse the additional decoded byte; a mere metadata hash is insufficient.
    with changes() as (change, touched):
        change(capture, read(capture) + gzip.compress(b'x', mtime=0))
        d = copy.deepcopy(original)
        report_path = shadow / 'batch-write/wide/native/result.json'; native_report = obj(report_path)
        compressed = file_record(capture); raw = q.stream_record(capture, True)
        native_report['streams']['normalized'] = dict(gzip_bytes=compressed['bytes'], gzip_sha256=compressed['sha256'],
                                                      raw_bytes=raw['bytes'], raw_sha256=raw['sha256'])
        change(report_path, native_report); change(shadow / (retained.NATIVE_NAME + '.stdout'), native_report)
        check = d['native_process']; check['summary'] = native_report
        stdout = file_record(shadow / (retained.NATIVE_NAME + '.stdout'))
        check.update(stdout_bytes=stdout['bytes'], stdout_sha256=stdout['sha256'])
        d['captures'] = {name: file_record(shadow / 'batch-write/wide' / name) for name in retained.CAPTURES}
        if context['mode'] == 'ci-original-pipeline':
            snapshot_path = shadow / 'original-native-report.json'; snapshot = obj(snapshot_path)
            snapshot['checks'] = [check if row.get('name') == retained.NATIVE_NAME else row for row in snapshot['checks']]
            change(snapshot_path, snapshot); d['context']['native_report'] = file_record(snapshot_path)
            seal_path = shadow / 'original-native.json'; seal = obj(seal_path)
            for name in [retained.NATIVE_NAME + '.stdout', 'original-native-report.json',
                         'batch-write/wide/native/result.json', 'batch-write/wide/native/normalized.bin.gz']:
                seal['files'][name].update(file_record(shadow / name))
            change(seal_path, seal); d['context']['native_seal_sha256'] = sha(read(seal_path))
        else:
            phase_path = shadow / context['phase_file']; phase = obj(phase_path)
            phase['completed_checks'] = [check]; change(phase_path, phase)
            d['context']['phase'] = file_record(phase_path)
        change(descriptor, d)
        reject('valid-gzip-suffix-all-envelopes-rehashed', inspect, touched)

    fixtures = output / 'fixture-controls'; (fixtures / 'wide/fixture').mkdir(parents=True)
    target = fixtures / 'wide/fixture/target'; target.write_bytes(b'owned-small-refusal-fixture')
    unknown = target.with_name('unknown'); unknown.write_bytes(b'must-remain')
    reject('unknown-fixture-member', lambda: retained.owned_fixture(fixtures, str(target)))
    exact(unknown.read_bytes(), b'must-remain', 'unknown fixture was modified'); unknown.unlink()
    target.unlink(); external = output / 'external'; external.write_bytes(b'must-remain-external')
    target.symlink_to(external)
    reject('symlink-fixture-target', lambda: retained.owned_fixture(fixtures, str(target)))
    exact(external.read_bytes(), b'must-remain-external', 'symlink target was modified')
    target.unlink(); target.write_bytes(b'owned-small-refusal-fixture')
    reject('foreign-fixture-path', lambda: retained.owned_fixture(fixtures, str(external)))
    exact(target.read_bytes(), b'owned-small-refusal-fixture', 'owned fixture was unexpectedly modified')
    exact([row['name'] for row in rows], list(CONTROLS), 'retained wide refusal domain omitted')
    exact(inspect(), before, 'restored native admission differs after mutation controls')
    exact(retained.admit_native(admission, expected_sha, invocation, root, manifest, corpus, stdout_dir), before,
          'real native artifacts changed during private refusal controls')
    result = dict(schema='hepta.runtime.batch-write-retained-wide-controls.v1', status='PASS',
        invocation=invocation, admission=file_record(admission), source_files=q.pins(root),
        controls=rows, refused=len(rows), accepted=3, new_native_calls=0, new_original_calls=0,
        elapsed_seconds=time.monotonic() - started)
    q.duration(result['elapsed_seconds'], 'retained wide evidence controls exceeded unchanged deadline')
    retained.write_new(output / 'result.json', result)
    print(json.dumps(result, sort_keys=True))
    return result


def evidence(folder, stdout, admission, invocation, *, root=ROOT):
    folder, stdout, admission, root = map(Path, (folder, stdout, admission, root))
    result = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.batch-write-retained-wide-controls.v1', status='PASS',
        invocation=invocation, admission=file_record(admission), source_files=q.pins(root),
        refused=len(CONTROLS), accepted=3, new_native_calls=0, new_original_calls=0)
    for key, value in expected.items(): exact(result.get(key), value, 'retained wide control evidence differs: ' + key)
    exact([row['name'] for row in result['controls']], list(CONTROLS), 'retained wide control domains changed')
    for row in result['controls']:
        exact(row.get('status'), 'REJECTED', 'retained wide damaged evidence was accepted')
        if not row.get('error'): raise ValueError('retained wide refusal reason missing')
    q.duration(result['elapsed_seconds'], 'retained wide control deadline differs')
    return dict(result=file_record(folder / 'result.json'), stdout=q.process_stdout(stdout, result),
                refused=len(CONTROLS), accepted=3, new_native_calls=0, new_original_calls=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'bundle', 'native-corpus', 'native-stdout-dir', 'admission', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--invocation', required=True)
    args = parser.parse_args()
    run(args.root, args.bundle, args.native_corpus, args.native_stdout_dir, args.admission, args.invocation, args.output)
