"""Fresh fixed-1.95 build and real canonicalize/root-order guard capture."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback
sys.dont_write_bytecode = True

SOURCE_FILES = ['run.py', 'cases.py', 'Cargo.toml', 'Cargo.lock', 'verify_sources.py', 'src/driver.rs',
                'original/config.rs', 'original/runtime.Cargo.lock']


def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(path):
    with Path(path).open('rb') as stream: return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
def dump(path, value):
    with Path(path).open('x') as stream: json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False); stream.write('\n')
def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def input_rows(cases):
    at = 16; rows = []
    for case in cases:
        begin = at; at += 40
        row = {key: case[key] for key in ('case_id', 'operation', 'name', 'domain')}
        row['source'] = {'offset': at, 'bytes': len(case['source']), 'sha256': sha(case['source'])}; at += len(case['source'])
        if len(case['source']) <= 4096: row['source']['hex'] = case['source'].hex()
        row['roots'] = []
        for root in case['roots']:
            at += 8; value = {'offset': at, 'bytes': len(root), 'sha256': sha(root)}; at += len(root)
            if len(root) <= 4096: value['hex'] = root.hex()
            row['roots'].append(value)
        row['record_offset'] = begin; row['record_bytes'] = at-begin; rows.append(row)
    return rows


def parse_output(raw, cases):
    assert raw[:16] == b'HFDGO001'+struct.pack('<Q', len(cases)); at = 16; rows = []
    for case in cases:
        begin = at; assert at+72 <= len(raw)
        cid, op, status, present, errno, short_len, chain_len, fd_before, fd_after = struct.unpack_from('<9Q', raw, at); at += 72
        assert (cid, op) == (case['case_id'], case['operation']) and status in (0, 1) and present in (0, 1)
        assert fd_before == fd_after and fd_before >= 3 and short_len+chain_len <= len(raw)-at
        short, chain = raw[at:at+short_len], raw[at+short_len:at+short_len+chain_len]; at += short_len+chain_len
        assert (not present and errno == 0) or (present and 0 < errno < 4096)
        if status == 0: assert not present and not short and not chain
        else: assert short and chain
        rows.append({'case_id': cid, 'operation': op, 'name': case['name'], 'domain': case['domain'], 'status': status,
            'errno_present': present, 'errno': errno, 'fd_before': fd_before, 'fd_after': fd_after,
            'short': {'offset': begin+72, 'bytes': short_len, 'sha256': sha(short), 'text': short.decode()},
            'chain': {'offset': begin+72+short_len, 'bytes': chain_len, 'sha256': sha(chain), 'text': chain.decode()},
            'record': {'offset': begin, 'bytes': at-begin, 'sha256': sha(raw[begin:at])}})
    assert at == len(raw); return rows


def marker_bytes(cases):
    return b''.join(b'HFDGMK01'+struct.pack('<3Q', case['case_id'], event, case['operation']) for case in cases for event in (0, 1))


def main():
    p = argparse.ArgumentParser()
    for name in ('root', 'output', 'rustc', 'cargo', 'strace'): p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--fixture-root', type=Path)
    a = p.parse_args()
    for name in ('root', 'output', 'rustc', 'cargo', 'strace'):
        setattr(a, name, getattr(a, name).absolute())
    source = a.root
    assert source == Path(__file__).absolute().parent and all('..' not in getattr(a, name).parts for name in ('root','output','rustc','cargo','strace'))
    assert source.is_dir() and not source.is_symlink()
    a.output.mkdir(mode=0o700); os.umask(0o077)
    fixtures = a.fixture_root.absolute() if a.fixture_root is not None else a.output/'fixtures'
    fixture_mode = 'existing-owned' if a.fixture_root is not None else 'new-owned'
    if a.fixture_root is not None:
        assert '..' not in fixtures.parts and fixtures != source and fixtures != a.output
        for parent in [*reversed(fixtures.parents), fixtures]:
            assert parent.is_dir() and not parent.is_symlink()
        info = fixtures.stat()
        assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
    execution = {'output_root': str(a.output), 'fixture_root': str(fixtures), 'fixture_mode': fixture_mode,
                 'rustc': str(a.rustc), 'cargo': str(a.cargo), 'strace': str(a.strace)}
    (a.output/'toolchain').mkdir()
    shutil.copyfile(a.strace, a.output/'toolchain/strace.bin')
    strace_pin = pin(a.strace)
    assert pin(a.output/'toolchain/strace.bin') == strace_pin
    dump(a.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    started = time.monotonic(); processes = []; source_pins = {name: pin(source/name) for name in SOURCE_FILES}
    def record(name, command, cwd, stdin_path=None):
        before = time.monotonic(); timed_out = False; child = None
        env_control = {'RUSTC': str(a.rustc), 'CARGO_TARGET_DIR': str(a.output/'target'), 'CARGO_BUILD_JOBS': '2',
                       'PATH': str(a.rustc.parent)+os.pathsep+os.environ.get('PATH', '')}
        stdout_path, stderr_path = a.output/(name+'.stdout'), a.output/(name+'.stderr')
        stdin = stdin_path.open('rb') if stdin_path else subprocess.DEVNULL
        try:
            with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
                child = subprocess.Popen(command, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr,
                    env=dict(os.environ, **env_control), start_new_session=True)
                try: child.wait(timeout=180)
                except subprocess.TimeoutExpired: timed_out = True; os.killpg(child.pid, signal.SIGKILL); child.wait()
        finally:
            if stdin_path: stdin.close()
        row = {'name': name, 'command': command, 'cwd': str(cwd), 'pid': child.pid, 'controlled_env': env_control,
            'timeout_seconds': 180, 'timed_out': timed_out, 'elapsed_seconds': time.monotonic()-before, 'exit_code': child.returncode,
            'stdin': {'path': str(stdin_path), **pin(stdin_path)} if stdin_path else None,
            'stdout': {'path': str(stdout_path), **pin(stdout_path)}, 'stderr': {'path': str(stderr_path), **pin(stderr_path)}}
        processes.append(row); (a.output/'processes.json').write_text(json.dumps(processes, sort_keys=True, indent=2)+'\n')
        assert not timed_out and child.returncode == 0, row
        return stdout_path.read_bytes()
    try:
        factory = load(source/'verify_sources.py', '_directory_guard_original_source')
        main_source, lock, proof = factory.assemble(source)
        crate = a.output/'crate'; (crate/'src').mkdir(parents=True)
        (crate/'src/main.rs').write_bytes(main_source); (crate/'Cargo.lock').write_bytes(lock)
        (crate/'Cargo.toml').write_bytes((source/'Cargo.toml').read_bytes())
        dump(a.output/'SOURCE.json', {'source_root': str(source), 'source_files': source_pins, 'original': proof,
            'materialized': {name: pin(crate/name) for name in ('src/main.rs', 'Cargo.toml', 'Cargo.lock')}, 'execution': execution})
        rustc = record('rustc-version', [str(a.rustc), '-Vv'], crate)
        cargo = record('cargo-version', [str(a.cargo), '-Vv'], crate)
        assert rustc.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n') and b'host: x86_64-unknown-linux-gnu\n' in rustc and cargo.startswith(b'cargo 1.95.0 ')
        record('strace-version', [str(a.strace), '-V'], crate)
        record('locked-build', [str(a.cargo), 'build', '--release', '--locked', '--manifest-path', str(crate/'Cargo.toml')], crate)
        assert (crate/'Cargo.lock').read_bytes() == lock
        binary = a.output/'target/release/hepta-directory-guard-original'; binary_pin = pin(binary)
        factory = load(source/'cases.py', '_directory_guard_input_cases')
        if fixture_mode == 'new-owned': factory.setup(fixtures)
        cases = factory.iter_cases(fixtures)
        before = factory.snapshot(fixtures); dump(a.output/'fixture-before.json', before)
        dump(a.output/'HOST.json', {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(), 'egid': os.getegid(),
            'uname': list(os.uname()), 'cwd': str(fixtures), 'scope': 'owned local Linux fixture',
            'status': Path('/proc/self/status').read_text()})
        with (a.output/'input.bin').open('xb') as stream: factory.encode(stream, cases)
        with (a.output/'input-cases.jsonl').open('x') as stream:
            for row in input_rows(cases): stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False)+'\n')
        trace = a.output/'original.strace'
        actual = record('original', [str(a.strace), '-f', '-qq', '-s', '4096', '-xx', '-e', 'trace=%file,close,write',
            '-o', str(trace), '--', str(binary)], fixtures, a.output/'input.bin')
        assert (a.output/'original.stderr').read_bytes() == marker_bytes(cases)
        rows = parse_output(actual, cases)
        with (a.output/'observations.jsonl').open('x') as stream:
            for row in rows: stream.write(json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False)+'\n')
        after = factory.snapshot(fixtures); dump(a.output/'fixture-after.json', after); assert before == after
        for path in (a.output/'input.bin', a.output/'original.stdout', a.output/'original.stderr', trace):
            with path.open('rb') as src, (a.output/(path.name+'.gz')).open('xb') as raw:
                with gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=6, mtime=0) as dst: shutil.copyfileobj(src, dst)
        assert pin(binary) == binary_pin and {name: pin(source/name) for name in SOURCE_FILES} == source_pins
        assert pin(a.strace) == strace_pin
        files = {path.name: pin(path) for path in sorted(a.output.iterdir()) if path.is_file()}
        result = {'schema': 'hepta.runtime.directory-move-guard-original-capture.v1', 'status': 'PASS',
            'cases': len(cases), 'unchanged_guard_helper_cases': sum(row['operation'] == 1 for row in rows),
            'uninstalled_config_projection_cases': sum(row['operation'] == 2 for row in rows),
            'successes': sum(row['status'] == 0 for row in rows), 'errors': sum(row['status'] == 1 for row in rows),
            'marker_pairs': len(cases), 'complete_error_bytes': sum(row['short']['bytes']+row['chain']['bytes'] for row in rows),
            'actual_processes': len(processes), 'actual_original_replays': 1, 'fresh_locked_builds': 1, 'version_processes': 3,
            'rustc_executable': {'path': str(a.rustc), **pin(a.rustc)},
            'cargo_executable': {'path': str(a.cargo), **pin(a.cargo)},
            'strace_executable': {'path': str(a.strace), **pin(a.strace)},
            'binary': {'path': str(binary), **binary_pin}, 'target_rustc_info': pin(a.output/'target/.rustc_info.json'),
            'source_files_unchanged': True, 'fixture_before_after_equal': True, 'source_root': str(source), 'fixture_root': str(fixtures),
            'output_root': str(a.output), 'fixture_mode': fixture_mode,
            'elapsed_seconds': time.monotonic()-started, 'trace_string_limit': 4096,
            'artifact_sha256': {name: value['sha256'] for name, value in files.items()},
            'artifact_bytes': {name: value['bytes'] for name, value in files.items()},
            'new_native_calls': 0, 'installed_config_startup_executed': False, 'public_sdk_executed': False,
            'public_filesystem_handler_executed': False, 'actual_move_executed': False}
        dump(a.output/'RESULT.json', result)
        print(json.dumps({key: value for key, value in result.items() if key not in ('artifact_sha256', 'artifact_bytes')}, sort_keys=True))
    except BaseException:
        dump(a.output/'FAILURE.json', {'traceback': traceback.format_exc(), 'elapsed_seconds': time.monotonic()-started,
            'completed_processes': len(processes)}); raise


if __name__ == '__main__': main()
