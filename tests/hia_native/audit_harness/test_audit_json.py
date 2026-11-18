"""Execute and compare native audit metadata derives against fresh original Rust derives."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY = 0xffffffff, 0xfffffffe
WORK = 1 << 20


def process(command, data, output, name, env=None):
    command = [str(value) for value in command]
    (output / (name + '.stdin')).write_bytes(data)
    started = time.monotonic()
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    timed = False
    try:
        stdout, stderr = child.communicate(data, timeout=180)
    except subprocess.TimeoutExpired:
        timed = True;child.kill();stdout, stderr = child.communicate()
    (output / (name + '.stdout')).write_bytes(stdout)
    (output / (name + '.stderr')).write_bytes(stderr)
    receipt = dict(command=command, pid=child.pid, exit_code=child.returncode, reaped=True,
        timeout_seconds=180, timed_out=timed, elapsed_seconds=time.monotonic() - started,
        stdin_bytes=len(data), stdin_sha256=SHA(data), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
        stderr_bytes=len(stderr), stderr_sha256=SHA(stderr))
    (output / (name + '.process.json')).write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    assert child.returncode == 0 and not timed and not stderr, receipt
    return stdout, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'runtime', 'oracle', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path[:0] = [str(Path(__file__).resolve().parent), str(args.runtime.resolve(strict=True) / 'scripts')]
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    from audit_json_cases import BASES, cases, frame, encoded
    report = dict(schema='hepta.request-audit.typed-json-actual-comparison.v1', status='FAIL', cases=[], controls=[],
        processes=[], whole_runtime_replaced=False, production_activated=False,
        old_stack_removal_qualified=False, result_storage_qualified=False, native_entries=0)
    save = lambda: (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    save();started = time.monotonic()
    try:
        rows = list(cases())
        request_bytes = b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        original, receipt = process([args.oracle], request_bytes, out, 'original')
        report['processes'].append(receipt)
        replies = original.splitlines()
        assert len(replies) == len(rows)
        with NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())) as module:
            report['module'] = module.metadata
            with module.session(output_capacity=WORK, workspace_capacity=WORK) as session:
                with (out / 'native.stdout').open('xb') as native:
                    for ordinal, ((label, wire), expected) in enumerate(zip(rows, replies, strict=True)):
                        report['native_entries'] += 1
                        try:
                            raw = session.invoke(wire);code = len(raw)
                        except (NativeRejected, NativeCapacityError) as error:
                            code, raw = error.code, b''
                        line = f'{code:08x}:'.encode() + raw.hex().encode()
                        native.write(line + b'\n')
                        record = dict(ordinal=ordinal, label=label, input_bytes=len(wire), input_sha256=SHA(wire),
                            code=code, output_bytes=len(raw), output_sha256=SHA(raw),
                            expected_sha256=SHA(expected), passed=line == expected)
                        report['cases'].append(record)
                        if not record['passed']:
                            (out / 'mismatch.json').write_text(json.dumps(dict(record=record, input_hex=wire.hex(),
                                expected=expected.decode(), actual=line.decode()), sort_keys=True, indent=2) + '\n')
                            raise AssertionError(record)
            for kind, base in enumerate(BASES, 1):
                wire = frame(kind, encoded(base))
                expected = next(replies[i] for i, (label, item) in enumerate(rows) if item == wire)
                raw_expected = bytes.fromhex(expected.split(b':')[1].decode())
                for capacity in (0, 1, 255, len(raw_expected) - 1, len(raw_expected)):
                    code, output, _ = module.invoke_raw(wire, output_capacity=capacity,
                        workspace_capacity=WORK, output_fill=0x69, workspace_fill=0xa7)
                    report['native_entries'] += 1
                    passed = (code == CAPACITY and output == b'\x69' * capacity) if capacity < len(raw_expected) else (code == len(raw_expected) and output == raw_expected)
                    row = dict(name='output-capacity', kind=kind, capacity=capacity, code=code, passed=passed)
                    report['controls'].append(row);assert passed, row
                code, output, workspace = module.invoke_raw(wire, output_capacity=WORK,
                    workspace_capacity=WORK - 1, output_fill=0x69, workspace_fill=0xa7)
                report['native_entries'] += 1
                passed = code == CAPACITY and output == b'\x69' * WORK and workspace == b'\xa7' * (WORK - 1)
                row = dict(name='workspace-capacity', kind=kind, passed=passed)
                report['controls'].append(row);assert passed, row
                code, output, _ = module.invoke_raw(frame(kind, b'{'), output_capacity=WORK,
                    workspace_capacity=WORK, output_fill=0x69, workspace_fill=0xa7)
                report['native_entries'] += 1
                passed = code == INVALID and output == b'\x69' * WORK
                row = dict(name='invalid-output-untouched', kind=kind, passed=passed)
                report['controls'].append(row);assert passed, row
                metadata = json.loads(args.manifest.read_bytes())
                executable = args.manifest.parent / metadata['standalone']['path']
                actual, receipt = process([executable], wire, out, 'native-elf-' + str(kind), env=dict(os.environ, PATH=''))
                assert actual == raw_expected
                report['processes'].append(receipt)
        assert (out / 'native.stdout').read_bytes() == original
        report.update(status='PASS', compared_cases=len(rows), actual_original_requests=len(rows),
            native_standalone_processes=4, controls_passed=len(report['controls']),
            exact_typed_projection_equal=True, accepted=sum(row['code'] != INVALID for row in report['cases']),
            elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'controls', 'module', 'processes')}, sort_keys=True))


if __name__ == '__main__':
    main()
