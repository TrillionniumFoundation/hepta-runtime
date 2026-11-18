# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Replay fresh Rust against this qualification's completed native wide case.

The unchanged aggregate owns the 180-second process group. This recipe adds
one original process and zero native processes. Every native request/response
and file byte remains mandatory, with an externally selected invocation and
admission digest; an earlier run cannot be selected by an inherited override.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for location in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))
import hia_native_batch_write_qualification as q
import hia_native_batch_write_build as build
import test_batch_write_wide as wide
from hia_native_batch_write_build import exact, require, read, obj, sha, file_record, canonical

ADMISSION = 'batch-write-native-wide-admission.json'
NATIVE_NAME = 'test_batch_write_wide.py'
CAPTURES = ('algorithm-controls.json', 'native/result.json', 'native/stderr.bin',
            'native/request.bin.gz', 'native/stdout.bin.gz', 'native/normalized.bin.gz', 'native/file.bin.gz')


def write_new(path, value):
    with Path(path).open('x') as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write('\n')


def current_invocation(invocation):
    require(type(invocation) is str and bool(invocation) and len(invocation) <= 256
            and not any(ord(char) < 32 for char in invocation), 'batch wide invocation is invalid')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        expected = os.environ.get('GITHUB_RUN_ID', '') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '')
        require(expected not in ('-', '-1'), 'batch wide current GitHub invocation is absent')
        exact(invocation, expected, 'batch wide admission belongs to another CI invocation')


def native_process(check, source_root, output_root, manifest_relative, stdout_dir):
    command = check.get('command')
    require(type(command) is list and len(command) == 8 and Path(command[0]).is_absolute(),
            'batch wide completed command is malformed')
    wanted = [command[0], '-I', '-B', str(Path(source_root) / 'tests/hia_native' / NATIVE_NAME),
              '--native', str(Path(output_root) / manifest_relative.parent / 'batch-write.elf'),
              '--output', str(Path(output_root) / 'batch-write/wide')]
    exact(command, wanted, 'batch wide completed command used another artifact or output')
    for key, value in dict(name=NATIVE_NAME, phase='native_components', exit_code=0,
                           timed_out=False, timeout_seconds=180).items():
        exact(check.get(key), value, 'batch wide completed process differs: ' + key)
    require(not check.get('start_error'), 'batch wide process was never started')
    q.duration(check['elapsed_seconds'], 'batch wide completed process exceeded its unchanged deadline')
    for channel in ('stdout', 'stderr'):
        actual = file_record(Path(stdout_dir) / (NATIVE_NAME + '.' + channel))
        exact(actual, dict(bytes=check[channel + '_bytes'], sha256=check[channel + '_sha256']),
              'batch wide completed process stream changed')
    exact(read(Path(stdout_dir) / (NATIVE_NAME + '.stderr')), b'', 'batch native wide emitted diagnostics')
    exact(check['summary'], obj(Path(stdout_dir) / (NATIVE_NAME + '.stdout')),
          'batch wide completed process summary changed')
    return check


def create_admission(root, output, manifest, source_files, check, context):
    """Called by the already admitted aggregate, or an actual owned local phase.

    CI context contains the workflow-selected original-native seal digest.
    The distinct local context contains a real completed phase receipt; neither
    mode creates or fabricates a native completion record.
    """
    root, output, manifest = map(lambda p: Path(p).resolve(strict=True), (root, output, manifest))
    exact(source_files, q.pins(root), 'batch wide admission source closure changed')
    relative = manifest.relative_to(output)
    require(relative.name == 'manifest.json', 'batch wide manifest location differs')
    invocation = context['invocation']; current_invocation(invocation)
    native_process(check, root, output, relative, output)
    evidence = q.wide_evidence(output / 'batch-write/wide', output / (NATIVE_NAME + '.stdout'), root=root)
    artifact = build.inspect_bundle(manifest, source_root=root)
    captures = {name: file_record(output / 'batch-write/wide' / name) for name in CAPTURES}
    admission = dict(schema='hepta.runtime.batch-write-wide-admission.v1', invocation=invocation,
        context=context, source_root=str(root), output_root=str(output), source_files=source_files,
        manifest_relative=str(relative), manifest=file_record(manifest), artifact_sha256=sha(canonical(artifact)),
        native_binary_sha256=build.ELF_SHA, native_process=check, native_evidence=evidence,
        captures=captures, native_processes_executed_by_original_recipe=0,
        native_requests_retained_from_current_qualification=1, original_timeout_seconds=180)
    path = output / ADMISSION
    write_new(path, admission)
    admit_native(path, file_record(path)['sha256'], invocation, root, manifest,
                 output / 'batch-write', output, execution=True)
    return path


def context_evidence(admission, stdout_dir):
    context = admission['context']; mode = context.get('mode')
    exact(context.get('invocation'), admission['invocation'], 'batch wide context invocation changed')
    if mode == 'ci-original-pipeline':
        exact(set(context), {'mode', 'invocation', 'native_seal_sha256', 'native_report'},
              'batch wide pipeline context shape differs')
        seal_path = Path(stdout_dir) / 'original-native.json'
        seal = obj(seal_path)
        exact(sha(read(seal_path)), context['native_seal_sha256'],
              'batch wide native seal differs from the workflow-selected artifact')
        exact(seal.get('schema'), 'hepta.runtime.original-native.v1', 'batch wide native seal schema differs')
        for key, value in dict(invocation=admission['invocation'], source=admission['source_root'],
                               output=admission['output_root']).items():
            exact(seal['context'].get(key), value, 'batch wide native seal context differs: ' + key)
        snapshot_path = Path(stdout_dir) / 'original-native-report.json'
        exact(file_record(snapshot_path), context['native_report'], 'batch wide immutable native report changed')
        sealed_report = seal['files']['original-native-report.json']
        exact({key: sealed_report[key] for key in ('bytes', 'sha256')}, context['native_report'],
              'batch wide completed native report is outside its seal')
        snapshot = obj(snapshot_path)
        for key, value in dict(status='NATIVE_COMPONENTS_PASS', native_components_status='PASS',
                               rust_comparison_status='PENDING').items():
            exact(snapshot.get(key), value, 'batch wide sealed native phase did not complete')
        exact(snapshot['qualification_pipeline']['invocation'], admission['invocation'],
              'batch wide completed native phase belongs to another run')
        exact(snapshot['checkout_head'], seal['context']['checkout_head'], 'batch wide native checkout differs')
        for name, identity in admission['source_files'].items():
            exact(snapshot['source_sha256'].get(name), identity['sha256'],
                  'batch wide current source is absent from the completed native phase: ' + name)
        rows = [row for row in snapshot['checks'] if row.get('name') == NATIVE_NAME]
        exact(rows, [admission['native_process']], 'batch wide completed check is absent or duplicated')
        wanted = ['test_batch_write_wide.py.stdout', 'test_batch_write_wide.py.stderr',
                  admission['manifest_relative'], *('batch-write/wide/' + name for name in CAPTURES)]
        for name in wanted:
            require(name in seal['files'], 'batch wide required evidence is outside the current native seal')
            exact(file_record(Path(stdout_dir) / name),
                  {key: seal['files'][name][key] for key in ('bytes', 'sha256')},
                  'batch wide current sealed evidence changed: ' + name)
        return dict(mode=mode, native_seal=file_record(seal_path), native_report=file_record(snapshot_path))
    exact(mode, 'owned-component-validation', 'batch wide admission has no current execution authority')
    exact(set(context), {'mode', 'invocation', 'phase_file', 'phase'}, 'batch wide local context shape differs')
    relative = Path(context['phase_file'])
    require(not relative.is_absolute() and '..' not in relative.parts and len(relative.parts) == 1,
            'batch wide local phase receipt is not owned by this qualification')
    phase_path = Path(stdout_dir) / relative
    exact(file_record(phase_path), context['phase'], 'batch wide actual local phase receipt changed')
    phase = obj(phase_path)
    exact(phase.get('status'), 'PASS', 'batch wide actual local phase did not complete')
    exact(phase.get('invocation'), admission['invocation'], 'batch wide actual local phase belongs to another run')
    exact(phase.get('source_files'), admission['source_files'], 'batch wide actual local phase used another source')
    exact(phase.get('source_root'), admission['source_root'], 'batch wide actual local phase source location differs')
    exact(phase.get('completed_checks'), [admission['native_process']], 'batch wide actual local check is incomplete')
    return dict(mode=mode, phase=file_record(phase_path))


def admit_native(path, expected_sha, invocation, root, manifest, native_corpus, stdout_dir, *, execution=False):
    path, root, manifest, native_corpus, stdout_dir = map(Path, (path, root, manifest, native_corpus, stdout_dir))
    exact(sha(read(path)), expected_sha, 'batch wide admission digest changed')
    admission = obj(path)
    exact(admission.get('schema'), 'hepta.runtime.batch-write-wide-admission.v1', 'batch wide admission schema differs')
    exact(admission.get('invocation'), invocation, 'batch wide admission belongs to another requested invocation')
    if execution: current_invocation(invocation)
    exact(admission.get('source_files'), q.pins(root), 'batch wide admission has another current source closure')
    exact(admission.get('native_binary_sha256'), build.ELF_SHA, 'batch wide admission has another native ELF')
    exact(admission.get('manifest'), file_record(manifest), 'batch wide admitted manifest changed')
    relative = Path(admission['manifest_relative'])
    require(not relative.is_absolute() and '..' not in relative.parts and relative.name == 'manifest.json',
            'batch wide admission manifest path is invalid')
    exact(admission['artifact_sha256'], sha(canonical(build.inspect_bundle(manifest, source_root=root))),
          'batch wide admitted compile/pack/image closure changed')
    if execution:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            exact(admission['context'].get('mode'), 'ci-original-pipeline',
                  'batch CI wide replay requires the workflow-selected native admission')
        exact(path.resolve(strict=True), stdout_dir.resolve(strict=True) / ADMISSION,
              'batch wide admission is outside this invocation')
        exact(str(root.resolve(strict=True)), admission['source_root'], 'batch wide replay source path differs')
        exact(str(stdout_dir.resolve(strict=True)), admission['output_root'], 'batch wide replay output path differs')
        exact(manifest.resolve(strict=True), stdout_dir.resolve(strict=True) / relative,
              'batch wide replay manifest is outside this invocation')
        exact(native_corpus.resolve(strict=True), stdout_dir.resolve(strict=True) / 'batch-write',
              'batch wide replay corpus is outside this invocation')
    authority = context_evidence(admission, stdout_dir)
    native_process(admission['native_process'], admission['source_root'], admission['output_root'], relative, stdout_dir)
    evidence = q.wide_evidence(native_corpus / 'wide', stdout_dir / (NATIVE_NAME + '.stdout'), root=root)
    exact(evidence, admission['native_evidence'], 'batch wide retained native observation changed')
    captures = {name: file_record(native_corpus / 'wide' / name) for name in CAPTURES}
    exact(captures, admission['captures'], 'batch wide retained native capture set changed')
    for key, value in dict(native_processes_executed_by_original_recipe=0,
                           native_requests_retained_from_current_qualification=1, original_timeout_seconds=180).items():
        exact(admission.get(key), value, 'batch wide admission execution accounting differs')
    return dict(admission=file_record(path), invocation=invocation, authority=authority,
                native=evidence, captures=captures, artifact_sha256=admission['artifact_sha256'])


def owned_fixture(native_corpus, expected_target):
    """Never unlink an unknown tree or follow a fixture/path symlink."""
    corpus = Path(native_corpus).absolute()
    exact(corpus.resolve(strict=True), corpus, 'batch retained fixture corpus contains a symlink')
    folder = corpus / 'wide/fixture'; target = folder / 'target'
    exact(str(target), expected_target, 'batch retained fixture path cannot be safely reproduced')
    for path in (corpus / 'wide', folder):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) and not stat.S_ISLNK(mode), 'batch retained fixture directory is not owned')
    exact(sorted(path.name for path in folder.iterdir()), ['target'], 'batch retained fixture has unknown members')
    require(stat.S_ISREG(target.lstat().st_mode), 'batch retained fixture target is not a regular file')
    return folder, target


def fixture_bytes(native_corpus, expected_target, capture):
    folder, target = owned_fixture(native_corpus, expected_target)
    parent_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    digest = hashlib.sha256(); count = 0
    try:
        descriptor = os.open('target', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), 'batch retained fixture descriptor is not regular')
        with os.fdopen(descriptor, 'rb', closefd=False) as actual, gzip.open(capture, 'rb') as expected:
            while True:
                a, b = actual.read(1 << 20), expected.read(1 << 20)
                exact(a, b, 'batch retained fixture bytes differ from the completed native capture')
                if not a: break
                digest.update(a); count += len(a)
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        exact(tuple(getattr(after, key) for key in fields), tuple(getattr(before, key) for key in fields),
              'batch retained fixture changed while its full content was being verified')
        current = os.stat('target', dir_fd=parent_fd, follow_symlinks=False)
        exact(tuple(getattr(current, key) for key in fields), tuple(getattr(before, key) for key in fields),
              'batch retained fixture path changed before its ownership check completed')
        exact(dict(bytes=count, sha256=digest.hexdigest()), q.WIDE_FILE,
              'batch retained fixture is not the entire completed native file')
        return dict(path=str(target), bytes=count, sha256=digest.hexdigest(),
                    mode=stat.S_IMODE(before.st_mode), device=before.st_dev, inode=before.st_ino,
                    complete_bytes_equal=True)
    finally:
        if descriptor is not None: os.close(descriptor)
        os.close(parent_fd)


def reset_owned_fixture(native_corpus, native_report, capture):
    verified = fixture_bytes(native_corpus, native_report['fixture_target'], capture)
    folder, target = owned_fixture(native_corpus, verified['path'])
    # The evidence remains immutable. Only this invocation's verified expanded
    # fixture is replaced, at the same path, by the unchanged test's initial
    # CRLF contents. No other directory/file is cleaned or recursively removed.
    current = target.lstat()
    exact((current.st_dev, current.st_ino, stat.S_IMODE(current.st_mode), current.st_size),
          (verified['device'], verified['inode'], verified['mode'], verified['bytes']),
          'batch retained fixture identity changed before replacement')
    target.unlink(); folder.rmdir()
    return verified


def compare(root, manifest, native_corpus, stdout_dir, admission, admission_sha, invocation, original, output):
    started = time.monotonic()
    root, manifest, native_corpus, stdout_dir, admission, original = map(
        lambda p: Path(p).resolve(strict=True), (root, manifest, native_corpus, stdout_dir, admission, original))
    output = Path(output).absolute(); output.mkdir(mode=0o700)
    report = dict(schema='hepta.runtime.batch-write-wide-retained-original.v1', status='RUNNING',
        invocation=invocation, source_root=str(root), native_corpus=str(native_corpus),
        native_stdout_dir=str(stdout_dir), manifest=str(manifest),
        admission_path=str(admission), admission_sha256=admission_sha,
        actual_native_requests=0, retained_native_requests=1, actual_original_requests=0,
        outer_timeout_seconds=180, inherits_outer_process_group=True,
        native_observation_mode='completed-current-qualification', original_replay_is_fresh=True,
        original_binary=dict(path=str(original), **file_record(original)),
        original_process_group=os.getpgrp(), production_activated=False, whole_runtime_replaced=False)
    def persist():
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    persist()
    try:
        before = admit_native(admission, admission_sha, invocation, root, manifest, native_corpus, stdout_dir, execution=True)
        report['admission_before'] = before; persist()
        native = obj(native_corpus / 'wide/native/result.json')
        retirement = reset_owned_fixture(native_corpus, native, native_corpus / 'wide/native/file.bin.gz')
        write_new(output / 'native-fixture-reset.json', dict(retirement,
            retained_capture=file_record(native_corpus / 'wide/native/file.bin.gz'),
            native_capture_unchanged=True, reconstructed_initial_content_by='unchanged-test_batch_write_wide.execute'))
        report['fixture_reset'] = file_record(output / 'native-fixture-reset.json'); persist()
        reference = wide.execute(original, native_corpus / 'wide/fixture', output / 'original', role='original')
        exact(reference['status'], 'ORIGINAL_RESPONSE_AND_FULL_FILE_PASS', 'batch fresh original wide did not complete')
        exact(obj(output / 'original/stderr.bin'),
              dict(status='PASS', original_owner_calls=1, responses=1, canceled=0),
              'batch fresh original wide owner summary differs')
        exact(reference['fixture_target'], native['fixture_target'], 'batch original wide used another actual path')
        report['actual_original_requests'] = 1; persist()
        compared = {name: wide.compare_streams(native_corpus / 'wide/native' / (name + '.bin.gz'),
                    output / 'original' / (name + '.bin.gz')) for name in ('request', 'normalized', 'file')}
        after = admit_native(admission, admission_sha, invocation, root, manifest, native_corpus, stdout_dir, execution=True)
        exact(after, before, 'batch current native evidence changed during fresh original replay')
        final_fixture = fixture_bytes(native_corpus, native['fixture_target'], native_corpus / 'wide/native/file.bin.gz')
        exact(final_fixture['mode'], retirement['mode'], 'batch native sealed fixture mode changed after original replay')
        exact(file_record(original), {key: report['original_binary'][key] for key in ('bytes', 'sha256')},
              'batch fresh original binary changed during wide replay')
        report.update(status='PASS', admission_after=after, compared=compared,
            original_result=file_record(output / 'original/result.json'), original_elapsed_seconds=reference['elapsed_seconds'],
            native_elapsed_seconds=native['elapsed_seconds'], fixture_after=final_fixture,
            exact_same_fixture_path=True, operations=50, content_bytes_per_operation=5242880,
            complete_response_bytes=1279265830, complete_final_file_bytes=262144100)
        q.duration(time.monotonic() - started, 'batch retained-native/original wide comparison exceeded unchanged deadline')
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started; persist()
    print(json.dumps(report, sort_keys=True))
    return report


def evidence(folder, manifest, native_corpus, stdout_dir, completed_stdout, *, root=ROOT, original_sha):
    """Recheck all retained bytes; this function executes zero semantic calls."""
    folder, manifest, native_corpus, stdout_dir, root = map(Path, (folder, manifest, native_corpus, stdout_dir, root))
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.batch-write-wide-retained-original.v1', status='PASS',
        actual_native_requests=0, retained_native_requests=1, actual_original_requests=1,
        outer_timeout_seconds=180, inherits_outer_process_group=True,
        native_observation_mode='completed-current-qualification', original_replay_is_fresh=True,
        production_activated=False, whole_runtime_replaced=False, exact_same_fixture_path=True,
        operations=50, content_bytes_per_operation=5242880, complete_response_bytes=1279265830,
        complete_final_file_bytes=262144100)
    for key, value in expected.items(): exact(report.get(key), value, 'batch retained wide accounting differs: ' + key)
    q.duration(report['elapsed_seconds'], 'batch retained wide replay deadline changed')
    admission = stdout_dir / ADMISSION
    admitted = admit_native(admission, report['admission_sha256'], report['invocation'], root, manifest, native_corpus, stdout_dir)
    exact(report['admission_before'], admitted, 'batch native wide pre-replay evidence changed')
    exact(report['admission_after'], admitted, 'batch native wide post-replay evidence changed')
    reference = q.wide_process_evidence(folder / 'original', original_sha, root, True)
    native_report = obj(native_corpus / 'wide/native/result.json'); original_report = obj(folder / 'original/result.json')
    exact(original_report['fixture_target'], native_report['fixture_target'], 'batch retained original wide path differs')
    exact(original_report['process_group'], report['original_process_group'], 'batch original wide escaped the owned group')
    exact(report['original_result'], file_record(folder / 'original/result.json'), 'batch original wide process result changed')
    exact(report['original_elapsed_seconds'], original_report['elapsed_seconds'], 'batch original wide time changed')
    exact(report['native_elapsed_seconds'], native_report['elapsed_seconds'], 'batch retained native time changed')
    exact(report['original_binary']['sha256'], original_sha, 'batch retained original wide executable differs')
    compared = {name: wide.compare_streams(native_corpus / 'wide/native' / (name + '.bin.gz'),
                folder / 'original' / (name + '.bin.gz')) for name in ('request', 'normalized', 'file')}
    exact(report['compared'], compared, 'batch complete retained/native original comparison changed')
    reset = obj(folder / 'native-fixture-reset.json')
    exact(report['fixture_reset'], file_record(folder / 'native-fixture-reset.json'), 'batch owned fixture reset receipt changed')
    for key, value in dict(path=native_report['fixture_target'], **q.WIDE_FILE, complete_bytes_equal=True,
                           retained_capture=file_record(native_corpus / 'wide/native/file.bin.gz'),
                           native_capture_unchanged=True,
                           reconstructed_initial_content_by='unchanged-test_batch_write_wide.execute').items():
        exact(reset.get(key), value, 'batch fixture ownership/reset record differs: ' + key)
    for key, value in dict(path=native_report['fixture_target'], **q.WIDE_FILE,
                           complete_bytes_equal=True, mode=reset['mode']).items():
        exact(report['fixture_after'].get(key), value, 'batch final sealed fixture differs: ' + key)
    for item in (reset, report['fixture_after']):
        require(type(item['device']) is int and item['device'] >= 0 and type(item['inode']) is int and item['inode'] > 0,
                'batch owned fixture identity is incomplete')
    return dict(result=file_record(folder / 'result.json'), native=admitted, original=reference,
        compared=compared, reset=file_record(folder / 'native-fixture-reset.json'),
        stdout=q.process_stdout(completed_stdout, report), new_native_requests=0, fresh_original_requests=1,
        retained_native_requests=1, retained_inspection_only=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'bundle', 'native-corpus', 'native-stdout-dir', 'admission', 'original', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--admission-sha256', required=True)
    parser.add_argument('--invocation', required=True)
    args = parser.parse_args()
    compare(args.root, args.bundle, args.native_corpus, args.native_stdout_dir, args.admission,
            args.admission_sha256, args.invocation, args.original, args.output)
