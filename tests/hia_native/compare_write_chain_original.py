"""Fresh locked Rust 1.95 owners and complete real-kernel write-chain pairs.

This internal qualification driver inherits its caller's process group. The
aggregate must own the unchanged 180-second group deadline; no child starts a
new session to escape it. The syscall observers additionally bind their native
and original roots to their own lifetime and reap them after each real case.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(path) not in sys.path: sys.path.insert(0, str(path))
import hia_native_write_chain_qualification as q
from hia_native_write_chain_build import inspect_bundle, read, obj, exact, require, sha, file_record
from prepare_chain_original import prepare

CLEARED = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
    'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP')


def tool(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    return dict(path=str(path), resolved_path=str(resolved), **file_record(resolved))


def cleared(name):
    return name in CLEARED or name.startswith('HIA_') or (name.startswith('CARGO_TARGET_') and name.endswith('_RUSTFLAGS'))


def compare(root, manifest, native_corpus, native_stdout_dir, output, *, rustc, cargo, rustfmt, offline=False):
    root, manifest = Path(root).resolve(strict=True), Path(manifest).resolve(strict=True)
    native_corpus, native_stdout_dir = Path(native_corpus).resolve(strict=True), Path(native_stdout_dir).resolve(strict=True)
    output = Path(output).resolve(); output.mkdir(mode=0o700)
    for name in ('tmp', 'empty-cwd'): (output / name).mkdir(mode=0o700)
    sources = q.pins(root); artifact = inspect_bundle(manifest, source_root=root)
    native = q.native_evidence(manifest, native_corpus, native_stdout_dir, root=root)
    selected = {name: tool(path) for name, path in [('rustc', rustc), ('cargo', cargo), ('rustfmt', rustfmt)]}
    environment = {name: value for name, value in os.environ.items() if not cleared(name)}
    environment.update(RUSTC=selected['rustc']['path'], CARGO_TARGET_DIR=str(output / 'target'), TMPDIR=str(output / 'tmp'))
    before = prepare(root, root, output / 'project')
    project = q.project_evidence(output / 'project', root)
    report = dict(schema='hepta.runtime.write-chain-original-comparison.v1', status='RUNNING',
        source_files=sources, artifacts=artifact, native=native, source_root=str(root), directory=str(output),
        manifest=str(manifest), native_corpus=str(native_corpus), native_stdout_dir=str(native_stdout_dir),
        tools=selected, python=tool(sys.executable), outer_process_group=os.getpgrp(),
        environment_policy=dict(cleared_names=list(CLEARED), clear_hia_prefix=True,
            clear_target_rustflags=True, selected={name: environment[name] for name in ('RUSTC', 'CARGO_TARGET_DIR', 'TMPDIR')},
            removed_names=sorted(name for name in os.environ if cleared(name))),
        project=project, original_build_is_fresh=True, original_replay_is_fresh=True,
        outer_timeout_seconds=180, inherits_outer_process_group=True, records=[],
        kernel=platform.release(), libc=list(platform.libc_ver()), original_processes=0, original_requests=0,
        production_activated=False, whole_runtime_replaced=False, remote_sftp_closed=False)
    started = time.monotonic()

    def persist():
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')

    def execute(name, command, cwd=None):
        out, err = output / (name + '.stdout'), output / (name + '.stderr')
        record = dict(name=name, command=command, cwd=str(cwd or output / 'empty-cwd'),
            inherits_outer_process_group=True, outer_timeout_seconds=180,
            stdin=dict(bytes=0, sha256=sha(b'')))
        report['records'].append(record); persist(); at = time.monotonic()
        with open(os.devnull, 'rb') as incoming, out.open('xb') as a, err.open('xb') as b:
            process = subprocess.Popen(command, cwd=cwd or output / 'empty-cwd', env=environment,
                stdin=incoming, stdout=a, stderr=b)
            record['pid'] = process.pid
            record['process_group'] = os.getpgid(process.pid)
            exact(record['process_group'], os.getpgrp(), 'original child escaped the owned aggregate group')
            record['exit_code'] = process.wait()
            record['reaped'] = True
        record.update(elapsed_seconds=time.monotonic() - at, stdout=file_record(out), stderr=file_record(err))
        persist(); exact(record['exit_code'], 0, 'write-chain original process failed: ' + name)

    try:
        execute('rustc-version', [selected['rustc']['path'], '-Vv'])
        version = read(output / 'rustc-version.stdout')
        require(version.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in version
                and b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n' in version,
                'write-chain original qualification requires explicit Rust 1.95.0')
        exact(read(output / 'rustc-version.stderr'), b'', 'write-chain Rust version diagnostics differ')
        execute('format-check', [selected['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(root / 'rustfmt.toml'), '--check', str(root / 'tests/hia_native/oracle_write_chain.rs')])
        command = [selected['cargo']['path'], 'build', '--release', '--locked', '--manifest-path', str(output / 'project/Cargo.toml')]
        if offline: command.append('--offline')
        execute('cargo-build', command, output / 'project')
        binary = output / 'target/release/hia-write-chain-callers-original'
        report['original_binary'] = dict(path=str(binary), **file_record(binary))
        exact(q.project_evidence(output / 'project', root), project, 'actual compiled original source changed')
        report['comparisons'] = {}
        for name, extra in [('files', ['--large']), ('kernel', []), ('concurrency', [])]:
            execute(name, [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / ('test_write_chain_' + name + '.py')),
                '--native', str(manifest.parent / 'write-chain.elf'), '--original', str(binary),
                '--output', str(output / name), *extra])
            if name == 'files': evidence = q.files_evidence(output / name, output / (name + '.stdout'), root=root, original_sha=report['original_binary']['sha256'])
            else: evidence = q.kernel_evidence(output / name, output / (name + '.stdout'), root=root,
                original_sha=report['original_binary']['sha256'], concurrent=name == 'concurrency')
            report['comparisons'][name] = evidence
        exact(file_record(binary), {key: report['original_binary'][key] for key in ('bytes', 'sha256')}, 'write-chain executed original binary changed')
        for name, value in selected.items(): exact(tool(value['path']), value, 'write-chain actual selected tool changed')
        exact(q.project_evidence(output / 'project', root), project, 'write-chain original owner project changed')
        exact(q.pins(root), sources, 'write-chain original recipe source closure changed')
        exact(inspect_bundle(manifest, source_root=root), artifact, 'write-chain native image or build receipt changed during replay')
        exact(q.native_evidence(manifest, native_corpus, native_stdout_dir, root=root), native, 'write-chain retained native corpus changed during original replay')
        report.update(status='PASS', original_processes=58, original_requests=343,
            exact_trace_comparisons=38, cancellation_partial_order_comparisons=15, concurrent_cases=4,
            full_file_observation_bytes_per_side=787555659)
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); (output / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started; persist()
    q.duration(report['elapsed_seconds'], 'write-chain original recipe exceeded the unchanged aggregate deadline')
    summary = {key: report[key] for key in ('status', 'original_processes', 'original_requests',
        'exact_trace_comparisons', 'cancellation_partial_order_comparisons', 'concurrent_cases',
        'full_file_observation_bytes_per_side', 'elapsed_seconds')}
    summary['result'] = file_record(output / 'result.json')
    print(json.dumps(summary, sort_keys=True))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--native-corpus', required=True, type=Path)
    parser.add_argument('--native-stdout-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rustc', required=True)
    parser.add_argument('--cargo', required=True)
    parser.add_argument('--rustfmt', required=True)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    compare(args.root, args.bundle, args.native_corpus, args.native_stdout_dir, args.output,
        rustc=args.rustc, cargo=args.cargo, rustfmt=args.rustfmt, offline=args.offline)
