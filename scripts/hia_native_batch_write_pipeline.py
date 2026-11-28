"""Connect batch-write artifacts to mandatory completed aggregate processes."""
from __future__ import annotations
from pathlib import Path
import os
import sys

import hia_native_batch_write_qualification as q
from hia_native_batch_write_build import exact, require, read, sha, obj, file_record

KEY = 'batch_write'
SOURCE = 'native/batch_write.hepta'
RUST_CHECK = 'batch-write-rust-compare'


def bundle(output, report):
    owner = report['modules'][KEY]
    exact(owner['builder'], KEY, 'batch-write aggregate builder differs')
    exact(owner['source'], SOURCE, 'batch-write aggregate source differs')
    relative = Path(owner['manifest'])
    require(not relative.is_absolute() and '..' not in relative.parts and relative.name == 'manifest.json',
            'batch-write aggregate manifest must be retained under its output')
    path = Path(output) / relative
    exact(sha(read(path)), owner['sha256'], 'batch-write registered manifest changed')
    return path


def commands_for(root, output, manifest):
    root, output, manifest = Path(root), Path(output), Path(manifest)
    folder = output / 'batch-write'; binary = manifest.parent / 'batch-write.elf'
    arguments = {
        'test_batch_write_controller.py': ['--registry', manifest.parent / 'registry.json', '--reference', root, '--output', folder / 'controller'],
        'test_batch_render.py': ['--manifest', manifest.parent / 'batch_render.json', '--reference', root, '--output', folder / 'render'],
        'test_utf8_probe.py': ['--new', manifest.parent / 'utf8_new.json', '--original', manifest.parent / 'utf8_original.json',
            '--composition', root / 'tests/hia_native/batch_utf8_composition.json', '--profiles-dir', root / 'scripts', '--output', folder / 'utf8'],
        'test_batch_write_files.py': ['--native', binary, '--reference', root, '--output', folder / 'files', '--large'],
        'test_batch_write_kernel.py': ['--native', binary, '--output', folder / 'kernel'],
        'test_batch_write_concurrency.py': ['--native', binary, '--output', folder / 'concurrency'],
        'test_batch_write_wide.py': ['--native', binary, '--output', folder / 'wide'],
        'test_batch_write_evidence.py': ['--root', root, '--bundle', manifest, '--corpus', folder,
            '--stdout-dir', output, '--output', folder / 'controls'],
    }
    return {name: [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name), *map(str, arguments[name])]
            for name in q.SUITES}


def test_commands(root, output, report):
    return commands_for(root, output, bundle(output, report))


def completed_process(output, report, completed, name, command):
    check, summary = completed(output, report, name)
    exact(check.get('command'), command, 'actual batch-write process command differs')
    for key, value in dict(exit_code=0, timed_out=False, timeout_seconds=180).items():
        exact(check.get(key), value, 'actual batch-write process did not complete under its deadline')
    require(not check.get('start_error'), 'batch-write process was not started')
    q.duration(check['elapsed_seconds'], 'actual batch-write process exceeded the original deadline')
    for channel in ('stdout', 'stderr'):
        raw = read(Path(output) / (name + '.' + channel))
        exact(check[channel + '_bytes'], len(raw), 'batch-write actual completed stream size differs')
        exact(check[channel + '_sha256'], sha(raw), 'batch-write actual completed stream digest differs')
    exact(read(Path(output) / (name + '.stderr')), b'', 'batch-write qualification process emitted diagnostics')
    exact(summary, obj(Path(output) / (name + '.stdout')), 'batch-write actual completed JSON envelope differs')
    return {key: check[key] for key in ('command', 'exit_code', 'timed_out', 'timeout_seconds', 'elapsed_seconds',
        'stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256')}


def qualification_evidence(root, output, report, completed):
    root, output = Path(root), Path(output)
    source_files = q.pins(root)
    for name, identity in source_files.items():
        exact(report['source_sha256'].get(name), identity['sha256'], 'batch-write source omitted from aggregate identity: ' + name)
    manifest = bundle(output, report)
    commands = test_commands(root, output, report)
    processes = {name: completed_process(output, report, completed, name, commands[name]) for name in q.SUITES}
    native = q.native_evidence(manifest, output / 'batch-write', output, root=root)
    controls = q.controls_evidence(output / 'batch-write/controls', native, output / 'test_batch_write_evidence.py.stdout', root=root)
    return dict(schema='hepta.runtime.batch-write-completed-evidence.v1', status='PASS', native=native,
        controls=controls, completed_processes=processes,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)


def original_command(root, output, report, rustc):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    from compare_batch_write_wide_retained import ADMISSION
    admission = output / ADMISSION
    binding = obj(admission)
    return [sys.executable, '-I', '-B', str(root / 'tests/hia_native/compare_batch_write_original.py'),
        '--root', str(root), '--bundle', str(bundle(output, report)),
        '--native-corpus', str(output / 'batch-write'), '--native-stdout-dir', str(output),
        '--output', str(output / 'batch-write-original'), '--rustc', str(rustc),
        '--cargo', str(rustc.with_name('cargo')), '--rustfmt', str(rustc.with_name('rustfmt')),
        '--wide-admission', str(admission), '--wide-admission-sha256', sha(read(admission)),
        '--wide-invocation', binding['invocation']]


def admit_current_wide(root, output, report, completed):
    """Bind the already completed native process to the current recipe/run."""
    from compare_batch_write_wide_retained import create_admission, write_new, current_invocation
    root, output = Path(root), Path(output)
    commands = test_commands(root, output, report)
    completed_process(output, report, completed, 'test_batch_write_wide.py', commands['test_batch_write_wide.py'])
    check, _ = completed(output, report, 'test_batch_write_wide.py')
    source_files = q.pins(root)
    for name, identity in source_files.items():
        exact(report['source_sha256'].get(name), identity['sha256'], 'batch wide current aggregate source differs')
    if 'original_shard' in report:
        invocation = report['original_shard']['invocation']; current_invocation(invocation)
        exact(report['qualification_pipeline']['invocation'], invocation, 'batch native and original invocations differ')
        context = dict(mode='ci-original-pipeline', invocation=invocation,
            native_seal_sha256=report['original_shard']['native_sha256'],
            native_report=file_record(output / 'original-native-report.json'))
    else:
        require(os.environ.get('GITHUB_ACTIONS') != 'true', 'batch CI wide replay requires the workflow-selected native seal')
        require(type(report.get('started_at')) is str and bool(report['started_at']),
                'batch aggregate has no current native invocation')
        invocation = 'aggregate:' + report['started_at']
        receipt = output / 'batch-write-native-phase.json'
        write_new(receipt, dict(schema='hepta.runtime.batch-native-completed-phase-snapshot.v1',
            status='PASS', invocation=invocation, source_root=str(root), source_files=source_files,
            completed_checks=[check], retained_observation_only=True, new_native_calls=0))
        context = dict(mode='owned-component-validation', invocation=invocation,
                       phase_file=receipt.name, phase=file_record(receipt))
    return create_admission(root, output, bundle(output, report), source_files, check, context)


def retained_original(root, output, report, rustc, completed):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    process = completed_process(output, report, completed, RUST_CHECK, original_command(root, output, report, rustc))
    folder = output / 'batch-write-original'
    evidence = q.original_evidence(folder, bundle(output, report), output / 'batch-write', output,
        output / (RUST_CHECK + '.stdout'), root=root)
    retained = obj(folder / 'result.json')
    exact(retained['source_root'], str(root), 'batch-write recipe ran against another source root')
    exact(retained['directory'], str(folder), 'batch-write retained result came from another invocation')
    exact(retained['manifest'], str(bundle(output, report)), 'batch-write recipe used another native artifact')
    exact(retained['native_corpus'], str(output / 'batch-write'), 'batch-write recipe used another native domain')
    exact(retained['native_stdout_dir'], str(output), 'batch-write recipe used another process capture')
    exact({name: item['path'] for name, item in retained['tools'].items()},
        {name: str(rustc.with_name(name)) for name in ('rustc', 'cargo', 'rustfmt')}, 'batch-write recipe selected another toolchain')
    return dict(evidence, completed_process=process, compiled_by_qualification_recipe=True)


def compare_original(root, output, report, rustc, completed, record_check, env):
    before = qualification_evidence(root, output, report, completed)
    exact(before, report[KEY + '_evidence'], 'batch-write native evidence changed before original replay')
    admit_current_wide(root, output, report, completed)
    record_check(output, report, name=RUST_CHECK, command=original_command(root, output, report, rustc), env=env, timeout=180)
    result = retained_original(root, output, report, rustc, completed)
    exact(qualification_evidence(root, output, report, completed), before, 'batch-write native evidence changed during original replay')
    return result
