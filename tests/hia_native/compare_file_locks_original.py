"""Fresh locked original-Rust compilation and complete file-lock comparisons."""
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
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from hia_native_file_lock_build import inspect_bundle, sha, read, obj, file_record, exact, require
from hia_native_file_lock_qualification import (
    pins, source_contract, state_evidence, kernel_evidence, STATE_SUMMARY, KEY_SUMMARY,
)
from run_file_lock_key import run as native_key, digest
from file_lock_key_kernel import run as kernel_pair
from file_lock_fixture import snapshot, retire

CLEARED = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR',
    'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC_BOOTSTRAP')

def tool(path):
    path = Path(path).absolute()
    resolved = path.resolve(strict=True)
    return {'path': str(path), 'resolved_path': str(resolved), **file_record(resolved)}

def same_stream(left, right):
    with Path(left).open('rb') as a, Path(right).open('rb') as b:
        while True:
            x, y = a.read(1 << 20), b.read(1 << 20)
            require(x == y, 'complete original/native file-lock output differs')
            if not x:
                break

def compare(root, bundle, state_corpus, output, *, rustc, cargo, rustfmt, offline=False):
    root, bundle = Path(root).resolve(strict=True), Path(bundle).resolve(strict=True)
    state_corpus, output = Path(state_corpus).resolve(strict=True), Path(output).resolve()
    output.mkdir(mode=0o700)
    for name in ('tmp', 'empty-cwd'):
        (output / name).mkdir(mode=0o700)
    before = pins(root)
    closure = source_contract(root)
    artifact = inspect_bundle(bundle, source_root=root)
    native_state = state_evidence(state_corpus, artifact, source_root=root)
    selected = {'rustc': tool(rustc), 'cargo': tool(cargo), 'rustfmt': tool(rustfmt)}
    environment = {key: value for key, value in os.environ.items() if key not in CLEARED and not key.startswith('HIA_')}
    environment.update(RUSTC=selected['rustc']['path'], CARGO_TARGET_DIR=str(output / 'target'),
        HIA_REFERENCE_RUNTIME=str(root), TMPDIR=str(output / 'tmp'))
    report = {'schema': 'hepta.runtime.file-lock-original-comparison.v1', 'status': 'RUNNING',
        'source_files': before, 'source_contract': closure, 'artifacts': artifact, 'native_state': native_state,
        'directory': str(output), 'source_root': str(root), 'tools': selected, 'libc': list(platform.libc_ver()),
        'kernel': platform.release(), 'records': [], 'cleared_environment_names': list(CLEARED),
        'removed_environment_names': sorted(key for key in os.environ if key in CLEARED or key.startswith('HIA_')),
        'selected_environment': {key: environment[key] for key in ('RUSTC', 'CARGO_TARGET_DIR', 'HIA_REFERENCE_RUNTIME', 'TMPDIR')},
        'original_build_is_fresh': True, 'original_replay_is_fresh': True,
        'concurrent_shared_owner_closed': False, 'canonical_to_state_composition_closed': False,
        'whole_runtime_replaced': False, 'production_activated': False}
    started = time.monotonic()

    def execute(name, command, budget, *, incoming=None, cwd=None):
        out, err = output / (name + '.stdout'), output / (name + '.stderr')
        record = {'name': name, 'command': command, 'cwd': str(cwd or output / 'empty-cwd'),
            'timeout_seconds': budget, 'input': digest(incoming) if incoming is not None else {'bytes': 0, 'sha256': sha(b'')}}
        report['records'].append(record)
        before_call = time.monotonic()
        try:
            with (Path(incoming).open('rb') if incoming is not None else open(os.devnull, 'rb')) as source, out.open('xb') as stdout, err.open('xb') as stderr:
                process = subprocess.run(command, stdin=source, stdout=stdout, stderr=stderr,
                    env=environment, cwd=cwd or output / 'empty-cwd', timeout=budget)
            record.update(exit_code=process.returncode, timed_out=False)
        except subprocess.TimeoutExpired:
            # subprocess.run kills and waits for its direct child. All
            # descendants also inherit the aggregate's owned process group.
            record.update(exit_code=None, timed_out=True)
            raise
        finally:
            record.update(elapsed=time.monotonic() - before_call, stdout=digest(out), stderr=digest(err))
        require(record['exit_code'] == 0, name + ' failed')
        return record

    try:
        execute('rustc-version', [selected['rustc']['path'], '-Vv'], 10)
        formatted = [root / 'tests/hia_native' / name for name in
            ('oracle_file_lock_state.rs', 'oracle_file_lock_key.rs', 'file_lock_oracle/build.rs')]
        execute('format-check', [selected['rustfmt']['path'], '--edition', '2024', '--config-path',
            str(root / 'rustfmt.toml'), '--check', *map(str, formatted)], 10)
        command = [selected['cargo']['path'], 'build', '--release', '--locked', '--manifest-path',
            str(root / 'tests/hia_native/file_lock_oracle/Cargo.toml')]
        if offline:
            command.append('--offline')
        execute('cargo-build', command, 120)
        binaries = {'state': output / 'target/release/hia-file-lock-original',
            'key': output / 'target/release/hia-file-lock-key-original'}
        report['binaries'] = {name: {'path': str(path), **file_record(path)} for name, path in binaries.items()}
        original = read(root / 'src/mcp/fs/text_editing.rs')
        begin = original.index(b'// Thread-safe file locking infrastructure')
        end = original.index(b'/// Test-only visibility', begin)
        remote = read(root / 'src/mcp/fs/remote.rs')
        at = remote.index(b'#[derive(Debug, Clone)]\npub enum PathSource {')
        until = remote.index(b'\nimpl PathSource {', at)
        key_at = remote.index(b'\tpub fn lock_key(&self) -> String {')
        key_end = remote.index(b'\n\t/// Human-readable path', key_at)
        bodies = {'file_lock_original.rs': original[begin:end], 'path_source_original.rs': remote[at:until],
            'path_key_original.rs': b'impl PathSource {\n' + remote[key_at:key_end] + b'\n}\n'}
        report['compiled_original_sources'] = {}
        for name, expected in bodies.items():
            found = list((output / 'target/release/build').glob('hia-file-lock-original-*/out/' + name))
            require(len(found) == 1, 'compiled original body was omitted or duplicated')
            exact(read(found[0]), expected, 'compiled original body changed')
            copied = output / name
            copied.write_bytes(expected)
            report['compiled_original_sources'][name] = {'build_path': str(found[0]), **file_record(copied)}
        for name, source in (('state-input.bin', 'requests.bin.gz'), ('state-native.bin', 'native-output.bin.gz')):
            with gzip.open(state_corpus / source, 'rb') as incoming, (output / name).open('xb') as target:
                shutil.copyfileobj(incoming, target, 1 << 20)
        execute('original-state', [str(binaries['state'])], 60, incoming=output / 'state-input.bin')
        exact(obj(output / 'original-state.stderr'), STATE_SUMMARY, 'actual original state summary differs')
        same_stream(output / 'original-state.stdout', output / 'state-native.bin')
        report['state_summary'] = obj(output / 'original-state.stderr')
        key = native_key(bundle.parent / 'file-lock-key.elf', output / 'key-bulk')
        before_fixture = snapshot(output / 'key-bulk/fixture')
        execute('original-key', [str(binaries['key'])], 180, incoming=output / 'key-bulk/requests.bin', cwd=output / 'key-bulk/fixture')
        exact(obj(output / 'original-key.stderr'), KEY_SUMMARY, 'actual original canonical summary differs')
        same_stream(output / 'original-key.stdout', output / 'key-bulk/native.stdout')
        exact(snapshot(output / 'key-bulk/fixture'), before_fixture, 'actual original canonical replay changed the fixture')
        report['key_summary'] = obj(output / 'original-key.stderr')
        report['fresh_native_key_bulk'] = key
        report['key_fixture'] = retire(output / 'key-bulk/fixture', output / 'key-bulk/fixture.json.gz')
        kernel = kernel_pair(bundle.parent / 'file-lock-key.elf', binaries['key'], output / 'kernel', retire_fixtures=True)
        report['kernel_summary'] = {key: value for key, value in kernel.items() if key != 'observations'}
        report['kernel_evidence'] = kernel_evidence(output / 'kernel', artifact['executables']['key']['inspection']['sha256'],
            report['binaries']['key']['sha256'], source_root=root)
        for name, path in binaries.items():
            exact(file_record(path), {key: report['binaries'][name][key] for key in ('bytes', 'sha256')}, 'original reference executable changed during replay')
        for name, value in selected.items():
            exact(tool(value['path']), value, 'original selected toolchain changed')
        exact(pins(root), before, 'file-lock sources changed during actual original comparison')
        exact(inspect_bundle(bundle, source_root=root), artifact, 'native file-lock artifacts changed during comparison')
        exact(state_evidence(state_corpus, artifact, source_root=root), native_state, 'original comparison changed complete native state corpus')
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', failure=repr(error))
        (output / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        report['elapsed'] = time.monotonic() - started
        (output / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))
    return report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--state-corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rustc', default=shutil.which('rustc'))
    parser.add_argument('--cargo', default=shutil.which('cargo'))
    parser.add_argument('--rustfmt', default=shutil.which('rustfmt'))
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    if not all((args.rustc, args.cargo, args.rustfmt)):
        parser.error('actual Rust compiler, Cargo and rustfmt are required')
    compare(args.root, args.bundle, args.state_corpus, args.output,
        rustc=args.rustc, cargo=args.cargo, rustfmt=args.rustfmt, offline=args.offline)
