"""Actual original/native syscall faults and post-death staging recovery."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_audit_remove import setup, snapshot, parse
from audit_remove_fault_cases import edge_cases as cases
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def framed(rows):
    return b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw) for raw in rows)


def launch(command, wire, directory, expected, *, umask=0o077):
    directory.mkdir(mode=0o700)
    (directory / 'stdin.bin').write_bytes(wire)
    started = time.monotonic();timed = False
    process = subprocess.Popen([str(x) for x in command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=dict(os.environ, PATH='', HEPTA_REQUEST_AUDIT_TRACE='0'), umask=umask)
    try:stdout, stderr = process.communicate(wire, timeout=20)
    except subprocess.TimeoutExpired:
        timed = True;process.kill();stdout, stderr = process.communicate()
    (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
    receipt = dict(command=[str(x) for x in command], pid=process.pid, exit_code=process.returncode,
        expected_exit_code=expected, reaped=True, timed_out=timed, timeout_seconds=20,
        elapsed_seconds=time.monotonic() - started, stdin_bytes=len(wire), stdin_sha256=SHA(wire),
        stdout_bytes=len(stdout), stdout_sha256=SHA(stdout), stderr_bytes=len(stderr), stderr_sha256=SHA(stderr),
        path_environment_empty=True)
    (directory / 'process.json').write_bytes(ENCODE(receipt))
    assert not timed and process.returncode == expected and not stderr, receipt
    return receipt, stdout


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before, identities = snapshot(root);pins = []
    def pin(values):
        for name, identity in values.items():
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            stat = os.fstat(fd);assert (stat.st_dev, stat.st_ino) == identity
            pins.append((fd, identity))
    try:
        pin(identities)
        config = directory / 'config.json';config.write_bytes(ENCODE(row['supervisor']))
        log = directory / 'kernel.json'
        command = [sys.executable, '-I', '-B', HERE / 'audit_remove_supervisor.py', '--fixture', root,
            '--config', config, '--log', log, '--timeout', '10', '--', executable, root]
        killed = 'recovery' in row
        receipt, stdout = launch(command, framed(row['operations']), directory / 'observed', 137 if killed else 0)
        observer = json.loads(log.read_bytes());assert observer['status'] == 'PASS'
        assert observer['all_selected_faults_reached'] and observer['child_reaped']
        assert observer['exit_code'] == (-9 if killed else 0)
        after, following = snapshot(root, identities)
        responses = parse(stdout)
        assert len(responses) == (0 if killed else len(row['operations']))
        selected = [dict(kind=e['kind'], ordinal=e['ordinal'], completion=e['completion'], held_files=e['held_files']) for e in observer['events'] if e['completion'] != 'kernel_continue']
        result = dict(selected_kernel_holding=selected, before=before, after=after, responses=responses, process=receipt,
            kernel_observer=observer, original_inodes_held_through_observation=True)
        outputs = [stdout]
        if killed:
            pin(following)
            recovery, data = launch([executable, root], framed(row['recovery']), directory / 'recovery', 0)
            final, _ = snapshot(root, following)
            answer = parse(data);assert len(answer) == len(row['recovery'])
            result.update(recovery_process=recovery, recovery_responses=answer, recovery_after=final)
            outputs.append(data)
        for fd, identity in pins:
            stat = os.fstat(fd);assert (stat.st_dev, stat.st_ino) == identity
        (directory / 'observation.json').write_bytes(ENCODE(result))
        return result, outputs
    finally:
        for fd, _ in pins:os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='hepta.request-audit.actual-record-removal-death-comparison.v1', status='FAIL', cases=[],
        whole_runtime_replaced=False, production_activated=False, result_storage_closed=False,
        public_request_dispatch_qualified=False, archive_anchoring_closed=False, audit_storage_closed=False,
        process_future_cancellation_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    started = time.monotonic();save()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        binaries = {str(path): SHA(path.read_bytes()) for path in (native, oracle)}
        report['executables'] = binaries
        rows = list(cases());assert len({row['name'] for row in rows}) == len(rows)
        (out / 'cases.json').write_bytes(ENCODE(rows))
        for index, row in enumerate(rows):
            folder = out / f'{index:04d}';folder.mkdir(mode=0o700)
            original, old_bytes = run(oracle, row, folder / 'original')
            actual, new_bytes = run(native, row, folder / 'native')
            fields = ['before', 'after', 'responses', 'selected_kernel_holding']
            if 'recovery' in row:fields += ['recovery_after', 'recovery_responses']
            passed = old_bytes == new_bytes and all(original[key] == actual[key] for key in fields)
            comparison = dict(name=row['name'], passed=passed, original=original, native=actual)
            report['cases'].append(comparison);save();assert passed, row['name']
        assert binaries == {str(path): SHA(path.read_bytes()) for path in (native, oracle)}
        report.update(status='PASS', compared_cases=len(rows),
            requests_per_implementation=sum(len(row['operations']) + len(row.get('recovery', [])) for row in rows),
            processes_per_implementation=len(rows) + sum('recovery' in row for row in rows),
            killed_requests_per_implementation=sum('recovery' in row for row in rows),
            exact_output_and_observed_filesystem_equal=True, all_selected_faults_reached=True, selected_kernel_held_files_equal=True,
            elapsed_seconds=time.monotonic() - started, executable_bytes_unchanged=True)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'executables')}, sort_keys=True))


if __name__ == '__main__':
    main()
