"""Connect write-chain artifacts to mandatory completed aggregate processes."""
from __future__ import annotations
from pathlib import Path
import sys

import hia_native_write_chain_qualification as q
from hia_native_write_chain_build import exact, require, read, sha, obj

KEY = 'write_chain'
SOURCE = 'native/write_chain.hepta'
RUST_CHECK = 'write-chain-rust-compare'


def bundle(output, report):
    owner = report['modules'][KEY]
    exact(owner['builder'], KEY, 'write-chain aggregate builder differs')
    exact(owner['source'], SOURCE, 'write-chain aggregate source differs')
    relative = Path(owner['manifest'])
    require(not relative.is_absolute() and '..' not in relative.parts and relative.name == 'manifest.json',
            'write-chain aggregate manifest must be retained under its output')
    path = Path(output) / relative
    exact(sha(read(path)), owner['sha256'], 'write-chain registered manifest changed')
    return path


def commands_for(root, output, manifest):
    root, output, manifest = Path(root), Path(output), Path(manifest)
    folder = output / 'write-chain'; binary = manifest.parent / 'write-chain.elf'
    arguments = {
        'test_shared_atomic.py': ['--manifest', manifest.parent / 'atomic_write_shared.json', '--output', folder / 'shared'],
        'test_write_chain_controller.py': ['--registry', manifest.parent / 'registry.json', '--output', folder / 'controller'],
        'test_write_chain_files.py': ['--native', binary, '--output', folder / 'files', '--large'],
        'test_write_chain_kernel.py': ['--native', binary, '--output', folder / 'kernel'],
        'test_write_chain_concurrency.py': ['--native', binary, '--output', folder / 'concurrency'],
        'test_write_chain_evidence.py': ['--root', root, '--bundle', manifest, '--corpus', folder,
            '--stdout-dir', output, '--output', folder / 'controls'],
    }
    return {name: [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / name), *map(str, arguments[name])]
            for name in q.SUITES}


def test_commands(root, output, report):
    return commands_for(root, output, bundle(output, report))


def completed_process(output, report, completed, name, command):
    check, summary = completed(output, report, name)
    exact(check.get('command'), command, 'actual write-chain process command differs')
    for key, value in dict(exit_code=0, timed_out=False, timeout_seconds=180).items():
        exact(check.get(key), value, 'actual write-chain process did not complete under its deadline')
    require(not check.get('start_error'), 'write-chain process was not started')
    q.duration(check['elapsed_seconds'], 'actual write-chain process exceeded the original deadline')
    for channel in ('stdout', 'stderr'):
        raw = read(Path(output) / (name + '.' + channel))
        exact(check[channel + '_bytes'], len(raw), 'write-chain actual completed stream size differs')
        exact(check[channel + '_sha256'], sha(raw), 'write-chain actual completed stream digest differs')
    exact(read(Path(output) / (name + '.stderr')), b'', 'write-chain qualification process emitted diagnostics')
    exact(summary, obj(Path(output) / (name + '.stdout')), 'write-chain actual completed JSON envelope differs')
    return {key: check[key] for key in ('command', 'exit_code', 'timed_out', 'timeout_seconds', 'elapsed_seconds',
        'stdout_bytes', 'stderr_bytes', 'stdout_sha256', 'stderr_sha256')}


def qualification_evidence(root, output, report, completed):
    root, output = Path(root), Path(output)
    source_files = q.pins(root)
    for name, identity in source_files.items():
        exact(report['source_sha256'].get(name), identity['sha256'], 'write-chain source omitted from aggregate identity: ' + name)
    manifest = bundle(output, report)
    commands = test_commands(root, output, report)
    processes = {name: completed_process(output, report, completed, name, commands[name]) for name in q.SUITES}
    native = q.native_evidence(manifest, output / 'write-chain', output, root=root)
    controls = q.controls_evidence(output / 'write-chain/controls', native, output / 'test_write_chain_evidence.py.stdout', root=root)
    return dict(schema='hepta.runtime.write-chain-completed-evidence.v1', status='PASS', native=native,
        controls=controls, completed_processes=processes,
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)


def original_command(root, output, report, rustc):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    return [sys.executable, '-I', '-B', str(root / 'tests/hia_native/compare_write_chain_original.py'),
        '--root', str(root), '--bundle', str(bundle(output, report)),
        '--native-corpus', str(output / 'write-chain'), '--native-stdout-dir', str(output),
        '--output', str(output / 'write-chain-original'), '--rustc', str(rustc),
        '--cargo', str(rustc.with_name('cargo')), '--rustfmt', str(rustc.with_name('rustfmt'))]


def retained_original(root, output, report, rustc, completed):
    root, output, rustc = Path(root), Path(output), Path(rustc)
    process = completed_process(output, report, completed, RUST_CHECK, original_command(root, output, report, rustc))
    folder = output / 'write-chain-original'
    evidence = q.original_evidence(folder, bundle(output, report), output / 'write-chain', output,
        output / (RUST_CHECK + '.stdout'), root=root)
    retained = obj(folder / 'result.json')
    exact(retained['source_root'], str(root), 'write-chain recipe ran against another source root')
    exact(retained['directory'], str(folder), 'write-chain retained result came from another invocation')
    exact(retained['manifest'], str(bundle(output, report)), 'write-chain recipe used another native artifact')
    exact(retained['native_corpus'], str(output / 'write-chain'), 'write-chain recipe used another native domain')
    exact(retained['native_stdout_dir'], str(output), 'write-chain recipe used another process capture')
    exact({name: item['path'] for name, item in retained['tools'].items()},
        {name: str(rustc.with_name(name)) for name in ('rustc', 'cargo', 'rustfmt')}, 'write-chain recipe selected another toolchain')
    return dict(evidence, completed_process=process, compiled_by_qualification_recipe=True)


def compare_original(root, output, report, rustc, completed, record_check, env):
    before = qualification_evidence(root, output, report, completed)
    exact(before, report[KEY + '_evidence'], 'write-chain native evidence changed before original replay')
    record_check(output, report, name=RUST_CHECK, command=original_command(root, output, report, rustc), env=env, timeout=180)
    result = retained_original(root, output, report, rustc, completed)
    exact(qualification_evidence(root, output, report, completed), before, 'write-chain native evidence changed during original replay')
    return result
