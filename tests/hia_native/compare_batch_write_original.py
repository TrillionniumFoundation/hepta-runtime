"""Fresh original Rust 1.95 batch body, renderer, and complete kernel replay.

The aggregate owns the unchanged 180-second process-group deadline. Every
compiler and replay process inherits that group. Kernel observers additionally
bind and reap their own native/original children. This internal driver does not
claim standalone descendant cancellation outside that aggregate contract.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(path) not in sys.path: sys.path.insert(0, str(path))
import hia_native_batch_write_qualification as q
import prepare_batch_body_original as body
import prepare_batch_render_original as render
from hia_native_batch_write_build import inspect_bundle, read, obj, exact, require, sha, file_record

CLEARED = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
    'CARGO_BUILD_RUSTFLAGS', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP', 'RUSTUP_TOOLCHAIN')
SUMMARY = ('status', 'original_processes', 'original_requests', 'body_processes', 'body_requests',
    'renderer_processes', 'renderer_requests', 'exact_trace_comparisons',
    'cancellation_partial_order_comparisons', 'concurrent_cases',
    'full_file_observation_bytes_per_side', 'wide_response_bytes', 'elapsed_seconds')


def tool(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    return dict(path=str(path), resolved_path=str(resolved), **file_record(resolved))


def cleared(name):
    return name in CLEARED or name.startswith('HIA_') or (name.startswith('CARGO_TARGET_') and name.endswith('_RUSTFLAGS'))


def compare(root, manifest, native_corpus, native_stdout_dir, output, *, rustc, cargo, rustfmt, offline=False):
    started = time.monotonic()
    root, manifest = Path(root).resolve(strict=True), Path(manifest).resolve(strict=True)
    native_corpus, native_stdout_dir = Path(native_corpus).resolve(strict=True), Path(native_stdout_dir).resolve(strict=True)
    output = Path(output).resolve(); output.mkdir(mode=0o700)
    for name in ('tmp', 'empty-cwd'): (output / name).mkdir(mode=0o700)
    sources = q.pins(root); artifact = inspect_bundle(manifest, source_root=root)
    native = q.native_evidence(manifest, native_corpus, native_stdout_dir, root=root)
    selected = {name: tool(path) for name, path in [('rustc', rustc), ('cargo', cargo), ('rustfmt', rustfmt)]}
    environment = {name: value for name, value in os.environ.items() if not cleared(name)}
    environment.update(RUSTC=selected['rustc']['path'], CARGO_TARGET_DIR=str(output / 'target'), TMPDIR=str(output / 'tmp'))
    body.prepare(root, output / 'body-project', root)
    render.prepare(root, output / 'render-project', root)
    projects = {name: q.original_project_evidence(output / (name + '-project'), root, render=name == 'render')
                for name in ('body', 'render')}
    report = dict(schema='hepta.runtime.batch-write-original-comparison.v1', status='RUNNING',
        source_files=sources, artifacts=artifact, native=native, source_root=str(root), directory=str(output),
        manifest=str(manifest), native_corpus=str(native_corpus), native_stdout_dir=str(native_stdout_dir),
        tools=selected, python=tool(sys.executable), outer_process_group=os.getpgrp(),
        environment_policy=dict(cleared_names=list(CLEARED), clear_hia_prefix=True,
            clear_target_rustflags=True, selected={name: environment[name] for name in ('RUSTC', 'CARGO_TARGET_DIR', 'TMPDIR')},
            removed_names=sorted(name for name in os.environ if cleared(name))),
        projects=projects, original_build_is_fresh=True, original_replay_is_fresh=True,
        outer_timeout_seconds=180, inherits_outer_process_group=True, records=[],
        kernel=platform.release(), libc=list(platform.libc_ver()), original_processes=0, original_requests=0,
        production_activated=False, whole_runtime_replaced=False, remote_sftp_closed=False)

    def persist():
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')

    def execute(name, command, cwd=None):
        out, err = output / (name + '.stdout'), output / (name + '.stderr')
        record = dict(name=name, command=command, cwd=str(cwd or output / 'empty-cwd'),
            inherits_outer_process_group=True, outer_timeout_seconds=180,
            stdin=dict(bytes=0, sha256=sha(b'')))
        report['records'].append(record); persist(); at = time.monotonic()
        process = None
        try:
            with open(os.devnull, 'rb') as incoming, out.open('xb') as a, err.open('xb') as b:
                process = subprocess.Popen(command, cwd=cwd or output / 'empty-cwd', env=environment,
                    stdin=incoming, stdout=a, stderr=b)
                record['pid'] = process.pid; record['process_group'] = os.getpgid(process.pid)
                exact(record['process_group'], os.getpgrp(), 'batch original child escaped the aggregate group')
                record['exit_code'] = process.wait(); record['reaped'] = True
        finally:
            if process is not None and process.poll() is None: process.kill(); process.wait()
            record.update(elapsed_seconds=time.monotonic() - at, stdout=file_record(out), stderr=file_record(err))
            persist()
        exact(record['exit_code'], 0, 'batch original process failed: ' + name)

    def replay_render(binary):
        name = 'render-replay'; at = time.monotonic()
        request = native_corpus / 'render/requests.gz'
        expected = native_corpus / 'render/native-output.gz'
        record = dict(name=name, command=[str(binary)], cwd=str(output / 'empty-cwd'),
            inherits_outer_process_group=True, outer_timeout_seconds=180,
            stdin=dict(q.RENDER_STREAMS['requests.gz']), input_capture=file_record(request))
        report['records'].append(record); persist()
        failures = []; sent = hashlib.sha256(); received = hashlib.sha256(); counts = dict(sent=0, received=0)
        process = None; thread = None
        try:
            with (output / 'render-replay.stderr').open('xb') as err:
                process = subprocess.Popen([str(binary)], cwd=output / 'empty-cwd', env=environment,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
                record['pid'] = process.pid; record['process_group'] = os.getpgid(process.pid)
                exact(record['process_group'], os.getpgrp(), 'batch renderer escaped the aggregate group')
                def pump():
                    try:
                        with gzip.open(request, 'rb') as handle:
                            while raw := handle.read(1 << 20):
                                process.stdin.write(raw); sent.update(raw); counts['sent'] += len(raw)
                        process.stdin.close()
                    except BaseException as error:
                        failures.append(repr(error))
                        if process.poll() is None: process.kill()
                thread = threading.Thread(target=pump); thread.start()
                with gzip.open(expected, 'rb') as truth, gzip.open(output / 'render-replay.stdout.gz', 'xb', compresslevel=1) as capture:
                    while want := truth.read(1 << 20):
                        actual = process.stdout.read(len(want))
                        capture.write(actual); received.update(actual); counts['received'] += len(actual)
                        exact(actual, want, 'batch original complete renderer output differs')
                    suffix = process.stdout.read(1)
                    if suffix: capture.write(suffix)
                    exact(suffix, b'', 'batch original renderer output has an unexpected suffix')
                record['exit_code'] = process.wait(); record['reaped'] = True
                thread.join(); exact(failures, [], 'batch renderer input pump failed')
                exact(record['exit_code'], 0, 'batch original renderer did not complete')
            exact(dict(bytes=counts['sent'], sha256=sent.hexdigest()), q.RENDER_STREAMS['requests.gz'], 'batch original renderer input was shortened')
            exact(dict(bytes=counts['received'], sha256=received.hexdigest()), q.RENDER_STREAMS['native-output.gz'], 'batch original renderer output was shortened')
            exact(obj(output / 'render-replay.stderr'), dict(status='PASS', cases=6738, input_bytes=50024901, output_bytes=12229698),
                'batch actual renderer owner summary differs')
        finally:
            if process is not None and process.poll() is None: process.kill(); process.wait()
            if thread is not None: thread.join()
            record.update(elapsed_seconds=time.monotonic() - at,
                stdout=file_record(output / 'render-replay.stdout.gz'), stderr=file_record(output / 'render-replay.stderr'),
                stdout_raw=dict(bytes=counts['received'], sha256=received.hexdigest()))
            persist()

    try:
        execute('rustc-version', [selected['rustc']['path'], '-Vv'])
        version = read(output / 'rustc-version.stdout')
        require(version.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in version
                and b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n' in version,
                'batch original qualification requires explicit Rust 1.95.0')
        exact(read(output / 'rustc-version.stderr'), b'', 'batch Rust version diagnostics differ')
        for name, oracle in [('body', 'oracle_batch_write.rs'), ('render', 'oracle_batch_render.rs')]:
            execute(name + '-format', [selected['rustfmt']['path'], '--check', '--edition=2024',
                '--config', 'hard_tabs=true,max_width=100', str(root / 'tests/hia_native' / oracle)])
        command = [selected['cargo']['path'], 'build', '--release', '--locked', '--manifest-path', str(output / 'body-project/Cargo.toml')]
        if offline: command.append('--offline')
        execute('cargo-build', command, output / 'body-project')
        body_binary = output / 'target/release/hia-batch-write-body-original'
        render_binary = output / 'original-renderer'
        execute('render-build', [selected['rustc']['path'], '-O', '--edition=2024', '-C', 'overflow-checks=off',
            str(output / 'render-project/oracle_batch_render.rs'), '-o', str(render_binary)])
        report['original_binaries'] = {name: dict(path=str(path), **file_record(path)) for name, path in [('body', body_binary), ('render', render_binary)]}
        replay_render(render_binary)
        report['comparisons'] = {}
        for name, extra in [('files', ['--reference', str(root)]), ('kernel', []), ('concurrency', []), ('wide', [])]:
            script = 'compare_batch_write_files.py' if name == 'files' else 'test_batch_write_' + name + '.py'
            execute(name, [sys.executable, '-I', '-B', str(root / 'tests/hia_native' / script),
                '--native', str(manifest.parent / 'batch-write.elf'), '--original', str(body_binary),
                '--output', str(output / name), *extra])
            if name == 'files': evidence = q.files_evidence(output / name, output / (name + '.stdout'), root=root, original_sha=report['original_binaries']['body']['sha256'])
            elif name == 'wide': evidence = q.wide_evidence(output / name, output / (name + '.stdout'), root=root, original_sha=report['original_binaries']['body']['sha256'])
            else: evidence = q.kernel_evidence(output / name, output / (name + '.stdout'), root=root,
                original_sha=report['original_binaries']['body']['sha256'], concurrent=name == 'concurrency')
            report['comparisons'][name] = evidence
        for name, binary in [('body', body_binary), ('render', render_binary)]:
            exact(file_record(binary), {key: report['original_binaries'][name][key] for key in ('bytes', 'sha256')}, 'batch executed original binary changed')
            exact(q.original_project_evidence(output / (name + '-project'), root, render=name == 'render'), projects[name], 'batch actual compiled original project changed')
        for name, value in selected.items(): exact(tool(value['path']), value, 'batch actual selected tool changed')
        exact(q.pins(root), sources, 'batch original recipe source closure changed')
        exact(inspect_bundle(manifest, source_root=root), artifact, 'batch native image or build receipt changed during replay')
        exact(q.native_evidence(manifest, native_corpus, native_stdout_dir, root=root), native, 'batch retained native corpus changed during original replay')
        report.update(status='PASS', original_processes=84, original_requests=7909,
            body_processes=83, body_requests=1171, renderer_processes=1, renderer_requests=6738,
            exact_trace_comparisons=58, cancellation_partial_order_comparisons=19, concurrent_cases=4,
            full_file_observation_bytes_per_side=10528942 + 262144100, wide_response_bytes=1279265830)
        q.duration(time.monotonic() - started, 'batch original recipe exceeded the unchanged aggregate deadline')
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); (output / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - started; persist()
    summary = {key: report[key] for key in SUMMARY}; summary['result'] = file_record(output / 'result.json')
    print(json.dumps(summary, sort_keys=True))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    for name in ('bundle', 'native-corpus', 'native-stdout-dir', 'output'): parser.add_argument('--' + name, required=True, type=Path)
    for name in ('rustc', 'cargo', 'rustfmt'): parser.add_argument('--' + name, required=True)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    compare(args.root, args.bundle, args.native_corpus, args.native_stdout_dir, args.output,
        rustc=args.rustc, cargo=args.cargo, rustfmt=args.rustfmt, offline=args.offline)
