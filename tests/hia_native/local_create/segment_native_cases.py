"""Capture the complete unchanged filesystem domain through the async entry. Live fixture directories are retained for strict evidence verification before retirement; this process does not execute Rust."""
from pathlib import Path
import argparse
import concurrent.futures
import gzip
import hashlib
import importlib.util
import json
import os
import resource
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
sys.dont_write_bytecode = True
CHUNK = 2 << 20
MASK = (1 << 64) - 1
SOURCE_PINS = {'kernel_cases.py': '514ab07d24e289423255c24e2f1841bdbe5f2aa48a772f8f99c93c4d7aff8180', 'race_cases.py': '71a4b28de51c4005d60b5b8aed209faebd868e6ffebe87ef98e6ea239febc9fe', 'fault_cases.py': '81ee8d0700d39436c656b6080fde7c16e80ffc4f647c71ff71f71939167b5e6a'}
SCOPE = dict(async_cancellation_qualified=False, public_handler_qualified=False, full_create_file_spec_qualified=False, production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return dict(bytes=len(raw), sha256=sha(raw))

def compact(item):
    return json.dumps(item, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def u(raw, at):
    return struct.unpack_from('<Q', raw, at)[0]

def wire(path, data):
    body = b'HLCARQ01' + struct.pack('<7Q', 1, len(path), len(data), 1, 0, 0, 0) + path + data
    return struct.pack('<Q', len(body)) + body

class Capture:

    def __init__(self, root):
        self.root = root
        self.artifact_sha256 = {}
        self.pending_retirement = []

    def admit(self, path):
        assert path.is_file() and (not path.is_symlink()) and (path.resolve() == path.absolute())
        raw = path.read_bytes()
        self.artifact_sha256[path.relative_to(self.root).as_posix()] = sha(raw)
        return raw

    def write(self, path, raw):
        with path.open('xb') as stream:
            stream.write(raw)
        assert self.admit(path) == raw

    def obj(self, path, item):
        self.write(path, compact(item) + b'\n')

    def compressed(self, path, raw):
        with gzip.open(path, 'xb', compresslevel=1) as stream:
            stream.write(raw)
        assert gzip.decompress(self.admit(path)) == raw

    def snapshot(self, driver, work, destination):
        destination.mkdir()
        rows = driver.snapshot(work, destination)
        for item in rows:
            if item['kind'] == 'file':
                raw = gzip.decompress(self.admit(destination / item['content']))
                assert pin(raw) == {key: item[key] for key in ('bytes', 'sha256')}
        return rows

    def defer_retirement(self, work):
        assert work.name == 'files' and stat.S_ISDIR(os.lstat(work).st_mode)
        assert work.resolve() == work.absolute() and work.is_relative_to(self.root)
        self.pending_retirement.append(work.relative_to(self.root).as_posix())

    def reread(self):
        for relative, digest in self.artifact_sha256.items():
            path = self.root / relative
            assert path.is_file() and (not path.is_symlink()) and (sha(path.read_bytes()) == digest)

def parse_streams(stdout, stderr, path, data, expected_generation=1):
    assert len(stdout) == 56 and stdout[:16] == struct.pack('<Q', 48) + b'HLCRER01'
    extent, kind, error, written, reserved = struct.unpack_from('<5Q', stdout, 16)
    assert extent == 48 and kind <= 3 and (reserved == 0)
    assert 1 <= error <= 4095 if kind == 1 else error == 0
    effects, journals = ([], [])
    offset = 0
    while offset < len(stderr):
        magic = stderr[offset:offset + 8]
        if magic == b'HLCREF01':
            raw = stderr[offset:offset + 96]
            assert len(raw) == 96
            fields = struct.unpack('<12Q', raw)
            _, sequence, action, a, b, c, d, ready, value, errno, token, zero = fields
            assert sequence == len(effects) + 1 and ready == 1 and (zero == 0) and (action in (1, 2, 3))
            assert errno <= 4095 and (not errno or (value == -errno & MASK and token == 0))
            if action == 1:
                assert (a, b, c, d) == (512, len(path), 524481, 438)
                assert errno or (token == 1 and value <= 2147483647)
            elif action == 2:
                assert a == 1 and 0 < c <= CHUNK and (d == token == 0)
                assert errno or value <= c
            else:
                assert (a, b, c, d, token) == (1, 0, 0, 0, 0)
                assert errno or value == 0
            effects.append(dict(sequence=sequence, action=action, args=[a, b, c, d], raw=value, errno=errno, token=token))
            offset += 96
        else:
            assert magic == b'HLCASR01'
            raw = stderr[offset:offset + 128]
            assert len(raw) == 128
            fields = struct.unpack('<16Q', raw)
            _, size, action, life, generation, seq, accepted, completed, result_kind, errno, start, end, core_phase, token, flags, zero = fields
            assert size == 128 and action in (1, 2, 3, 4, 8, 9, 10, 11) and (life in (1, 2, 3, 5))
            assert generation == expected_generation and zero == 0
            assert completed <= accepted <= len(data) and 0 <= start <= end <= len(data)
            assert end - start <= CHUNK and result_kind <= 3 and (errno <= 4095) and (core_phase <= 5) and (token <= 1)
            assert 1 <= errno <= 4095 if result_kind == 1 else errno == 0
            assert flags & ~33490691 == 0
            assert flags >> 8 & 255 <= 4 and 1 <= flags >> 16 & 255 <= 5 and (flags >> 24 == 0)
            journals.append(dict(action=action, life=life, generation=generation, sequence=seq, accepted=accepted, completed=completed, kind=result_kind, errno=errno, ticket_start=start, ticket_end=end, core_phase=core_phase, token=token, flags=flags))
            offset += 128
    assert offset == len(stderr) and journals
    assert (journals[0]['action'], journals[0]['life'], journals[0]['sequence']) == (10, 1, 0)
    queue = [row for row in journals if row['action'] in (1, 2)]
    assert queue and queue[0]['action'] == 1
    for index, row in enumerate(queue):
        assert row['sequence'] == index + 1 and row['life'] == 2
        if index == 0:
            assert row['accepted'] == row['ticket_start'] == row['ticket_end'] == 0
        else:
            assert row['action'] == 2 and row['ticket_start'] == (index - 1) * CHUNK
            assert row['ticket_end'] == min(index * CHUNK, len(data)) and row['accepted'] == row['ticket_start']
    progress = 0
    opened = False
    closed = False
    for effect in effects:
        action = effect['action']
        if action == 1:
            assert not opened and (not closed) and (progress == 0)
            if not effect['errno']:
                opened = True
        elif action == 2:
            assert opened and (not closed)
            a, b, c, d = effect['args']
            assert b == 513 + len(path) + progress
            end = min((progress // CHUNK + 1) * CHUNK, len(data))
            assert c == end - progress
            if not effect['errno']:
                progress += effect['raw']
        else:
            assert opened and (not closed)
            closed = True
    if b'\x00' in path:
        assert (kind, error, written) == (2, 0, 0) and (not effects) and (len(queue) == 1)
    else:
        assert effects and effects[0]['action'] == 1
        assert closed == opened and progress == written
    if kind == 0:
        assert written == len(data) and opened and closed
        assert len(queue) == 1 + (len(data) + CHUNK - 1) // CHUNK
    return dict(kind=kind, errno=error, written=written, effects=effects, journals=journals)

def execute(binary, folder, stdin, work, umask, cap, *, limit=None):
    cap.compressed(folder / 'stdin.bin.gz', stdin)

    def child_limits():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    began = time.monotonic()
    child = subprocess.Popen([str(binary)], cwd=work, env={'PATH': '', 'LC_ALL': 'C'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=umask, preexec_fn=child_limits if limit is not None else None)
    timed_out = False
    try:
        stdout, stderr = child.communicate(stdin, timeout=60)
    except subprocess.TimeoutExpired:
        timed_out = True
        child.kill()
        stdout, stderr = child.communicate(timeout=10)
    process = subprocess.CompletedProcess([str(binary)], child.returncode, stdout, stderr)
    elapsed = time.monotonic() - began
    cap.write(folder / 'stdout.bin', process.stdout)
    cap.write(folder / 'stderr.bin', process.stderr)
    execution = dict(command=[str(binary)], cwd=str(work), environment={'PATH': '', 'LC_ALL': 'C'}, timeout_seconds=60, elapsed_seconds=elapsed, exit_code=process.returncode, timed_out=timed_out, umask=umask, stdin=pin(stdin), stdout=pin(process.stdout), stderr=pin(process.stderr))
    if limit is not None:
        execution.update(rlimit_fsize=[limit, limit], sigxfsz='ignored')
    cap.obj(folder / 'execution.json', execution)
    assert not timed_out and process.returncode == 0, (folder.name, execution)
    return (process.stdout, process.stderr, execution)

def load_driver(source, name):
    file = source / 'tests/hia_native/local_create' / name
    assert sha(file.read_bytes()) == SOURCE_PINS[name]
    spec = importlib.util.spec_from_file_location('async_fixture_' + name.removesuffix('.py'), file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def run_kernel(binary, output, driver, cap):
    output.mkdir()
    rows = []
    for index, spec in enumerate(driver.cases()):
        folder = output / str(index)
        folder.mkdir()
        work = folder / 'files'
        driver.setup(work, spec)
        before = cap.snapshot(driver, work, folder / 'before')
        stdin = wire(spec['path'], spec['data'])
        stdout, stderr, execution = execute(binary, folder, stdin, work, spec['umask'], cap)
        row = parse_streams(stdout, stderr, spec['path'], spec['data'])
        after = cap.snapshot(driver, work, folder / 'after')
        row.update(name=spec['name'], before=before, after=after, execution=execution)
        cap.obj(folder / 'result.json', row)
        cap.defer_retirement(work)
        rows.append(row)
    assert len(rows) == 285
    return rows

def run_faults(binary, output, driver, cap):
    output.mkdir()
    rows = []
    for index, (limit, size) in enumerate(driver.cases()):
        folder = output / str(index)
        folder.mkdir()
        work = folder / 'files'
        work.mkdir()
        data = driver.payload(size)
        stdin = wire(b'created', data)
        stdout, stderr, execution = execute(binary, folder, stdin, work, 18, cap, limit=limit)
        row = parse_streams(stdout, stderr, b'created', data)
        assert (row['kind'], row['errno']) == ((1, 27) if size > limit else (0, 0))
        assert row['written'] == min(size, limit)
        raw = (work / 'created').read_bytes()
        cap.write(folder / 'created.bin', raw)
        assert raw == data[:min(size, limit)]
        assert stat.S_IMODE((work / 'created').stat().st_mode) == 420
        row.update(index=index, limit=limit, input_bytes=size, file=pin(raw), execution=execution)
        cap.obj(folder / 'result.json', row)
        cap.defer_retirement(work)
        rows.append(row)
    assert len(rows) == 8
    return rows

def run_races(binary, output, cap):
    output.mkdir()
    rows = []
    for number in range(32):
        folder = output / str(number)
        folder.mkdir()
        work = folder / 'files'
        work.mkdir()
        payloads = [b'first caller bytes', b'second caller bytes']
        inputs = [wire(b'created', value) for value in payloads]
        processes = [subprocess.Popen([str(binary)], cwd=work, env={'PATH': '', 'LC_ALL': 'C'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=18) for _ in range(2)]
        assert all((process.poll() is None for process in processes)) and len({p.pid for p in processes}) == 2
        barrier = threading.Barrier(3)

        def send(index):
            barrier.wait(timeout=30)
            began = time.monotonic()
            stdout, stderr = processes[index].communicate(inputs[index], timeout=60)
            return (stdout, stderr, time.monotonic() - began)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(send, index) for index in range(2)]
                barrier.wait(timeout=30)
                answers = [f.result(timeout=65) for f in futures]
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
        parsed = []
        for index, (stdout, stderr, elapsed) in enumerate(answers):
            cap.compressed(folder / (str(index) + '.stdin.bin.gz'), inputs[index])
            cap.write(folder / (str(index) + '.stdout.bin'), stdout)
            cap.write(folder / (str(index) + '.stderr.bin'), stderr)
            execution = dict(command=[str(binary)], cwd=str(work), environment={'PATH': '', 'LC_ALL': 'C'}, timeout_seconds=60, elapsed_seconds=elapsed, exit_code=processes[index].returncode, pid=processes[index].pid, umask=18, stdin=pin(inputs[index]), stdout=pin(stdout), stderr=pin(stderr))
            cap.obj(folder / (str(index) + '.execution.json'), execution)
            assert processes[index].returncode == 0
            row = parse_streams(stdout, stderr, b'created', payloads[index])
            row['execution'] = execution
            parsed.append(row)
        results = [(row['kind'], row['errno']) for row in parsed]
        assert sorted(results) == [(0, 0), (1, 17)]
        winner = results.index((0, 0))
        raw = (work / 'created').read_bytes()
        assert raw == payloads[winner]
        cap.write(folder / 'created.bin', raw)
        row = dict(number=number, winner=winner, processes=parsed, final_file=pin(raw), both_processes_live_before_input_release=True)
        cap.obj(folder / 'result.json', row)
        cap.defer_retirement(work)
        rows.append(row)
    return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    sys.path.insert(0, str(root / 'scripts'))
    from hia_native_local_create_build import source_evidence
    component = source_evidence(root)
    assert sha(binary.read_bytes()) == component['executable_sha256']
    output.mkdir(parents=True, exist_ok=False)
    cap = Capture(output)
    report = dict(schema='hepta.runtime.local-create-segment-native-capture.v1', status='RUNNING', source_root=str(root), output=str(output), executable=dict(path=str(binary), **pin(binary.read_bytes())), component=component, cancellation_signals_sent=0, injected_completions=False, actual_kernel_operations=True, original_rust_execution_performed=False, **SCOPE)
    began = time.monotonic()
    try:
        kernel = load_driver(root, 'kernel_cases.py')
        fault = load_driver(root, 'fault_cases.py')
        assert sha((root / 'tests/hia_native/local_create/race_cases.py').read_bytes()) == SOURCE_PINS['race_cases.py']
        kr = run_kernel(binary, output / 'kernel', kernel, cap)
        fr = run_faults(binary, output / 'fault', fault, cap)
        rr = run_races(binary, output / 'race', cap)
        all_rows = kr + fr + [r for pair in rr for r in pair['processes']]
        assert source_evidence(root) == component and sha(binary.read_bytes()) == component['executable_sha256']
        cap.reread()
        assert len(cap.pending_retirement) == 325
        report.update(status='CAPTURED', kernel_cases=285, race_pairs=32, fault_cases=8, actual_native_root_processes=357, actual_effects=sum((len(r['effects']) for r in all_rows)), complete_control_journals=sum((len(r['journals']) for r in all_rows)), elapsed_seconds=time.monotonic() - began, timeout_seconds_per_process=60, driver=pin(Path(__file__).read_bytes()), source_pins=SOURCE_PINS, pending_fixture_directories=cap.pending_retirement, artifact_sha256=dict(sorted(cap.artifact_sha256.items())))
    except BaseException as error:
        report.update(status='FAIL', error=repr(error), elapsed_seconds=time.monotonic() - began, artifact_sha256=dict(sorted(cap.artifact_sha256.items())))
        traceback.print_exc()
        raise
    finally:
        (output / 'result.json').write_bytes(compact(report) + bytes([10]))
        print(json.dumps({k: v for k, v in report.items() if k not in ('component', 'artifact_sha256', 'pending_fixture_directories')}, sort_keys=True), flush=True)
if __name__ == '__main__':
    main()
