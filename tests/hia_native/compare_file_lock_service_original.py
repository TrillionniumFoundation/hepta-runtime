"""Fresh locked original owner build, complete service replay and kernel pairs."""
from __future__ import annotations
import argparse
import gzip
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / 'scripts', Path(__file__).resolve().parent):
    if str(path) not in sys.path: sys.path.insert(0, str(path))
from hia_native_file_lock_service_build import inspect_bundle, read, obj, sha, file_record, exact, require
from hia_native_file_lock_service_qualification import (
    pins, source_contract, native_evidence, kernel_evidence, ORIGINAL_CONCURRENT,
)
from compare_file_locks_original import CLEARED, tool
from file_lock_key_cases import setup
from file_lock_fixture import snapshot, retire
from file_lock_service_kernel import run as kernel_pair


def complete_equal(packed, path):
    digest = __import__('hashlib').sha256(); count = 0
    with gzip.open(packed, 'rb') as expected, Path(path).open('rb') as actual:
        while block := expected.read(1 << 20):
            exact(actual.read(len(block)), block, 'complete service original/native output differs')
            digest.update(block); count += len(block)
        exact(actual.read(), b'', 'original service output has extra bytes')
    return {'bytes': count, 'sha256': digest.hexdigest()}


def expand(source, target):
    with gzip.open(source, 'rb') as incoming, Path(target).open('xb') as output:
        shutil.copyfileobj(incoming, output, 1 << 20)
    return file_record(target)


def operation_counts(path):
    import struct
    counts = [0] * 8
    with Path(path).open('rb') as incoming:
        while header := incoming.read(16):
            require(len(header) == 16, 'original service stdin header truncated')
            size, tag = struct.unpack('<QQ', header)
            require(64 <= size <= (5 << 20) + 64, 'original service stdin extent differs')
            packet = incoming.read(size); require(len(packet) == size, 'original service stdin row truncated')
            op = struct.unpack_from('<Q', packet, 8)[0]
            require(1 <= op <= 7, 'private lifecycle operation entered original service replay')
            counts[op] += 1
    return counts


def compare(root, bundle, native_corpus, native_stdout, state_corpus, output, *, rustc, cargo, rustfmt, offline=False):
    root, bundle = Path(root).resolve(strict=True), Path(bundle).resolve(strict=True)
    native_corpus, native_stdout = Path(native_corpus).resolve(strict=True), Path(native_stdout).resolve(strict=True)
    state_corpus, output = Path(state_corpus).resolve(strict=True), Path(output).resolve()
    output.mkdir(mode=0o700)
    for name in ('tmp', 'empty-cwd'): (output / name).mkdir(mode=0o700)
    before = pins(root); closure = source_contract(root); artifact = inspect_bundle(bundle, source_root=root)
    native = native_evidence(bundle, native_corpus, state_corpus, source_root=root, stdout=native_stdout)
    selected = {'rustc': tool(rustc), 'cargo': tool(cargo), 'rustfmt': tool(rustfmt)}
    environment = {key: value for key, value in os.environ.items() if key not in CLEARED and not key.startswith('HIA_')}
    environment.update(RUSTC=selected['rustc']['path'], CARGO_TARGET_DIR=str(output / 'target'),
        HIA_REFERENCE_RUNTIME=str(root), TMPDIR=str(output / 'tmp'))
    report = {'schema': 'hepta.runtime.file-lock-service-original-comparison.v1', 'status': 'RUNNING',
        'source_files': before, 'source_contract': closure, 'artifacts': artifact, 'native': native,
        'directory': str(output), 'source_root': str(root), 'native_corpus': str(native_corpus),
        'state_corpus': str(state_corpus), 'native_stdout': str(native_stdout),
        'tools': selected, 'libc': list(platform.libc_ver()), 'kernel': platform.release(), 'records': [],
        'cleared_environment_names': list(CLEARED),
        'removed_environment_names': sorted(key for key in os.environ if key in CLEARED or key.startswith('HIA_')),
        'selected_environment': {key: environment[key] for key in ('RUSTC', 'CARGO_TARGET_DIR', 'HIA_REFERENCE_RUNTIME', 'TMPDIR')},
        'original_build_is_fresh': True, 'original_replay_is_fresh': True,
        'serial_byte_compared_rows': 0, 'concurrent_property_operations': 0,
        'asynchronous_wait_scheduler_closed': False, 'upper_file_io_closed': False,
        'whole_runtime_replaced': False, 'production_activated': False}
    started = time.monotonic()

    def execute(name, command, budget, *, incoming=None, cwd=None):
        out, err = output / (name + '.stdout'), output / (name + '.stderr')
        record = {'name': name, 'command': command, 'cwd': str(cwd or output / 'empty-cwd'),
            'timeout_seconds': budget, 'input': file_record(incoming) if incoming is not None else {'bytes': 0, 'sha256': sha(b'')}}
        report['records'].append(record); start = time.monotonic()
        try:
            with (Path(incoming).open('rb') if incoming is not None else open(os.devnull, 'rb')) as source, \
                 out.open('xb') as a, err.open('xb') as b:
                process = subprocess.run(command, cwd=cwd or output / 'empty-cwd', env=environment,
                    stdin=source, stdout=a, stderr=b, timeout=budget)
            record.update(exit_code=process.returncode, timed_out=False)
        except subprocess.TimeoutExpired:
            # subprocess.run kills and reaps the direct child. Descendants
            # inherit the aggregate's owned process group; no new session is
            # created to escape an outer 180-second cancellation.
            record.update(exit_code=None, timed_out=True); raise
        finally:
            record.update(elapsed=time.monotonic() - start, stdout=file_record(out), stderr=file_record(err))
        require(record['exit_code'] == 0, name + ' failed')
        return record

    try:
        execute('rustc-version', [selected['rustc']['path'], '-Vv'], 10)
        require(read(output / 'rustc-version.stdout').startswith(b'rustc 1.95.0 '), 'service original qualification requires explicit Rust 1.95.0')
        formatted = [root / 'tests/hia_native/oracle_file_lock_service.rs', root / 'tests/hia_native/file_lock_service_oracle/build.rs']
        execute('format-check', [selected['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(root / 'rustfmt.toml'), '--check', *map(str, formatted)], 10)
        command = [selected['cargo']['path'], 'build', '--release', '--locked', '--manifest-path',
            str(root / 'tests/hia_native/file_lock_service_oracle/Cargo.toml')]
        if offline: command.append('--offline')
        execute('cargo-build', command, 120)
        original = output / 'target/release/hia-file-lock-service-original'
        report['original_binary'] = {'path': str(original), **file_record(original)}
        text = read(root / 'src/mcp/fs/text_editing.rs'); at = text.index(b'// Thread-safe file locking infrastructure')
        until = text.index(b'/// Test-only visibility', at)
        remote = read(root / 'src/mcp/fs/remote.rs'); start = remote.index(b'#[derive(Debug, Clone)]\npub enum PathSource {')
        end = remote.index(b'\nimpl PathSource {', start)
        key = remote.index(b'\tpub fn lock_key(&self) -> String {'); key_end = remote.index(b'\n\t/// Human-readable path', key)
        bodies = {'file_lock_original.rs': text[at:until], 'path_source_original.rs': remote[start:end],
            'path_key_original.rs': b'impl PathSource {\n' + remote[key:key_end] + b'\n}\n'}
        report['compiled_original_sources'] = {}
        for name, expected in bodies.items():
            found = list((output / 'target/release/build').glob('hia-file-lock-service-original-*/out/' + name))
            require(len(found) == 1, 'actual original owner body omitted or duplicated')
            exact(read(found[0]), expected, 'actual compiled original owner body changed')
            (output / name).write_bytes(expected)
            report['compiled_original_sources'][name] = {'build_path': str(found[0]), **file_record(output / name)}
        report['state'] = []
        for session in obj(native_corpus / 'result.json')['results']['state']['sessions']:
            name = 'session-' + str(session['session']); folder = native_corpus / 'state' / name
            source = output / (name + '.stdin'); expand(folder / 'requests.bin.gz', source)
            execute('original-' + name, [str(original)], 60, incoming=source, cwd=native_corpus / 'state')
            compared = complete_equal(folder / 'native-output.bin.gz', output / ('original-' + name + '.stdout'))
            counts = operation_counts(source); rows = sum(counts)
            exact(compared['bytes'], rows * 76, 'original service state row count differs')
            summary = {'status': 'PASS', 'rows': rows, 'original_owner_operations': rows,
                'operation_counts': counts, 'borrowed_guards': True, 'extra_strong_observer_refs': 0}
            exact(obj(output / ('original-' + name + '.stderr')), summary, 'actual original state session summary differs')
            report['state'].append({'session': session['session'], 'rows': rows, 'summary': summary, 'output': compared})
            report['serial_byte_compared_rows'] += rows
        exact(report['serial_byte_compared_rows'], 51783, 'original state service domain omitted')
        canonical = native_corpus / 'canonical'; captured = json.loads(gzip.decompress(read(canonical / 'fixture.json.gz')))
        exact(captured['path'], str(canonical / 'fixture'), 'native canonical corpus was relocated before actual replay')
        fixture = setup(canonical / 'fixture'); exact(snapshot(fixture), captured['entries'], 'canonical original fixture differs from the actual native fixture')
        source = output / 'canonical.stdin'; expand(canonical / 'process/requests.bin.gz', source)
        execute('original-canonical', [str(original)], 180, incoming=source, cwd=fixture)
        compared = complete_equal(canonical / 'process/native-output.bin.gz', output / 'original-canonical.stdout')
        counts = operation_counts(source); exact(sum(counts), 179431, 'original canonical service rows omitted')
        summary = {'status': 'PASS', 'rows': 179431, 'original_owner_operations': 179431,
            'operation_counts': counts, 'borrowed_guards': True, 'extra_strong_observer_refs': 0}
        exact(obj(output / 'original-canonical.stderr'), summary, 'actual original canonical service summary differs')
        exact(snapshot(fixture), captured['entries'], 'actual original canonical replay changed its fixture')
        report['canonical'] = {'rows': 179431, 'summary': summary, 'output': compared,
            'fixture': retire(fixture, output / 'canonical-original-fixture.json.gz')}
        report['serial_byte_compared_rows'] += 179431
        concurrent = native_corpus / 'concurrent'; captured = json.loads(gzip.decompress(read(concurrent / 'fixture.json.gz')))
        exact(captured['path'], str(concurrent / 'fixture'), 'native concurrent corpus was relocated before actual replay')
        fixture = concurrent / 'fixture'; fixture.mkdir(); (fixture / 'file').write_bytes(b'original'); (fixture / 'file').chmod(0o644)
        (fixture / 'alias').symlink_to('file'); exact(snapshot(fixture), captured['entries'], 'concurrent original fixture differs from actual native fixture')
        execute('original-concurrent', [str(original), '--concurrent'], 60, cwd=fixture)
        exact(obj(output / 'original-concurrent.stdout'), ORIGINAL_CONCURRENT, 'actual original concurrent property domain differs')
        exact(read(output / 'original-concurrent.stderr'), b'', 'actual original concurrency emitted a diagnostic')
        exact(snapshot(fixture), captured['entries'], 'actual original concurrency changed its fixture')
        report['concurrent'] = ORIGINAL_CONCURRENT
        report['concurrent_fixture'] = retire(fixture, output / 'concurrent-original-fixture.json.gz')
        report['concurrent_property_operations'] = 6210
        kernel = kernel_pair(bundle.parent / 'file-lock-service.elf', original, output / 'kernel')
        report['kernel_summary'] = {key: value for key, value in kernel.items() if key != 'observations'}
        report['kernel_evidence'] = kernel_evidence(output / 'kernel', artifact['executable']['inspection']['sha256'],
            report['original_binary']['sha256'], source_root=root)
        exact(file_record(original), {key: report['original_binary'][key] for key in ('bytes', 'sha256')}, 'executed original binary changed during replay')
        for name, selected_tool in selected.items(): exact(tool(selected_tool['path']), selected_tool, 'selected original compiler changed')
        exact(pins(root), before, 'service original replay sources changed')
        exact(inspect_bundle(bundle, source_root=root), artifact, 'service original replay native artifacts changed')
        exact(native_evidence(bundle, native_corpus, state_corpus, source_root=root, stdout=native_stdout), native, 'original replay changed complete native corpus')
        exact(report['serial_byte_compared_rows'], 231214, 'original sequential service domain omitted')
        report.update(status='PASS', kernel_original_owner_operations=224, total_original_owner_operations=237648)
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error)); (output / 'failure.txt').write_text(traceback.format_exc()); raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    summary = {key: report[key] for key in ('status', 'elapsed', 'serial_byte_compared_rows',
        'concurrent_property_operations', 'kernel_original_owner_operations', 'total_original_owner_operations')}
    summary['result'] = file_record(output / 'result.json')
    print(json.dumps(summary, sort_keys=True))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--native-corpus', type=Path, required=True)
    parser.add_argument('--native-stdout', type=Path, required=True)
    parser.add_argument('--state-corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', default=shutil.which('rustc'))
    parser.add_argument('--cargo', default=shutil.which('cargo'))
    parser.add_argument('--rustfmt', default=shutil.which('rustfmt'))
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    if not all((args.rustc, args.cargo, args.rustfmt)):
        parser.error('the actual original Rust compiler, Cargo and rustfmt are required')
    compare(args.root, args.bundle, args.native_corpus, args.native_stdout, args.state_corpus, args.output,
        rustc=args.rustc, cargo=args.cargo, rustfmt=args.rustfmt, offline=args.offline)
