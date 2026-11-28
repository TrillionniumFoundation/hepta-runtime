# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare actual original safe DTO admission with real native child execution."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
ACTION, REQUEST, REPLY = 256, (160 << 20) + 65536, (176 << 20) + 65536
WORK, CHILD_CAP = 256 << 20, 64 << 20


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def query(tool, body):
    tool = tool.encode()
    return b'HRSDQ001' + struct.pack('<3Q', len(tool), len(body), 0) + tool + body


def locks_released(state):
    if state is None:
        return
    for name in ('controller.owner.lock', 'controller.lock'):
        fd = os.open(state / name, os.O_RDWR | os.O_CLOEXEC)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def original(oracle, config, rows, output, name, *, startup_refusal=False, domain='safe_dto'):
    if oracle is None:
        from result_storage_fixture import retained_json
        return retained_json(domain, output.name, rows, output, name, startup_refusal=startup_refusal)
    command = [str(oracle)] + (['--runtime-config', str(config)] if config else [])
    raw = b''.join(encode(row) + b'\n' for row in rows)
    (output / (name + '.stdin.jsonl')).write_bytes(raw)
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed = False
    try:
        stdout, stderr = process.communicate(raw, timeout=180)
    except subprocess.TimeoutExpired:
        timed = True
        process.kill()
        stdout, stderr = process.communicate()
    (output / (name + '.stdout.jsonl')).write_bytes(stdout)
    (output / (name + '.stderr.log')).write_bytes(stderr)
    receipt = dict(command=command, pid=process.pid, exit_code=process.returncode, reaped=True,
        timed_out=timed, timeout_seconds=180, elapsed_seconds=time.monotonic() - started,
        stdin_bytes=len(raw), stdin_sha256=SHA(raw), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
        stderr_bytes=len(stderr), stderr_sha256=SHA(stderr))
    (output / (name + '.process.json')).write_bytes(encode(receipt) + b'\n')
    if startup_refusal:
        assert process.returncode != 0 and not timed and not stdout, receipt
        assert b'runtime config must declare at least one host' in stderr, receipt
        receipt['startup_refusal'] = True
        return None, receipt
    assert process.returncode == 0 and not timed and not stderr, receipt
    result = [json.loads(line) for line in stdout.splitlines()]
    assert len(result) == len(rows)
    return result, receipt


class ConfigChild:
    def __init__(self, executable, config, state, output):
        self.command = [str(executable)] + (['--runtime-config', str(config)] if config else [])
        self.state, self.output = state, output
        self.input_log = (output / 'native-config.stdin.bin').open('xb')
        self.output_log = (output / 'native-config.stdout.bin').open('xb')
        self.error_log = (output / 'native-config.stderr.log').open('xb')
        self.started = time.monotonic()
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.error_log)
        self.calls = 0
        self.timed_out = False
        self.receipt = None

    def read(self, count):
        out = bytearray()
        while len(out) < count:
            remaining = 180 - (time.monotonic() - self.started)
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                self.timed_out = True
                raise TimeoutError('native configuration child deadline')
            block = os.read(self.process.stdout.fileno(), count - len(out))
            if not block:
                raise EOFError('native configuration child ended before its response')
            self.output_log.write(block)
            out.extend(block)
        return bytes(out)

    def invoke(self, wire):
        frame = struct.pack('<Q', len(wire)) + wire
        self.input_log.write(frame)
        self.process.stdin.write(frame)
        self.process.stdin.flush()
        size, = struct.unpack('<Q', self.read(8))
        assert 32 <= size <= CHILD_CAP
        result = self.read(size)
        self.calls += 1
        return result

    def close(self, failed=False):
        self.process.stdin.close()
        if failed:
            self.process.kill()
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.timed_out = True
            self.process.kill()
            code = self.process.wait()
        tail = self.process.stdout.read()
        self.output_log.write(tail)
        self.process.stdout.close()
        self.input_log.close();self.output_log.close();self.error_log.close()
        receipt = dict(command=self.command, pid=self.process.pid, exit_code=code, reaped=True,
            timed_out=self.timed_out, timeout_seconds=180, shutdown_timeout_seconds=10,
            elapsed_seconds=time.monotonic() - self.started, calls=self.calls, failed_parent=failed)
        for channel, suffix in (('stdin', 'bin'), ('stdout', 'bin'), ('stderr', 'log')):
            raw = (self.output / ('native-config.' + channel + '.' + suffix)).read_bytes()
            receipt[channel] = dict(bytes=len(raw), sha256=SHA(raw))
        locks_released(self.state)
        receipt['controller_locks_released'] = True
        self.receipt = receipt
        (self.output / 'native-config.process.json').write_bytes(encode(receipt) + b'\n')
        if not failed:
            assert code == 0 and not self.timed_out and not tail and receipt['stderr']['bytes'] == 0, receipt


class Bridge:
    def __init__(self, owner, value, config, exceptions):
        self.owner, self.value, self.config, self.exceptions = owner, value, config, exceptions
        self.entries = self.value_calls = self.config_calls = 0

    def read(self, offset, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + offset, size)

    def write(self, offset, raw):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + offset, raw, len(raw))

    def word(self, offset, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + offset)
        if value is None:
            return cell.value
        cell.value = value

    def invoke(self, module, wire):
        try:
            raw = module.invoke(wire)
            return len(raw), raw
        except self.exceptions as error:
            return error.code, b''

    def enter(self, wire):
        self.entries += 1
        return self.invoke(self.owner, wire)

    def complete(self):
        fields = struct.unpack('<8s11Q', self.read(ACTION, 96))
        magic, seq, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = fields
        assert magic == b'HRSDA001' and seq > 0 and child in (1, 2)
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and capacity == CHILD_CAP and 24 <= size <= (8 << 20) + 24
        wire = self.read(start, size)
        assert wire[:8] == (b'HSJVAL01' if child == 1 else b'HRCFGQ01')
        operation, length = struct.unpack_from('<2Q', wire, 8)
        assert length == size - 24
        if child == 1:
            assert operation == 1
            self.value_calls += 1
            result, reply = self.invoke(self.value, wire)
        else:
            assert operation in (1, 2, 10)
            self.config_calls += 1
            reply = self.config.invoke(wire)
            result = len(reply)
        self.write(REPLY, reply)
        self.word(ACTION + 64, seq)
        self.word(ACTION + 72, result)
        return dict(sequence=seq, child=child, operation=operation, input_bytes=len(wire), input_sha256=SHA(wire),
            output_bytes=len(reply), output_sha256=SHA(reply), child_code=result)

    def run(self, wire):
        code, raw = self.enter(wire)
        calls = []
        while code == CALL:
            assert len(calls) < 4
            calls.append(self.complete())
            code, raw = self.enter(wire)
        return code, raw, calls


def private_controls(bridge, wire):
    rows = []

    def reset():
        bridge.write(0, bytes(512))

    def observe(name, actual, expected):
        row = dict(name=name, expected=expected, actual=actual, passed=actual == expected)
        rows.append(row)
        assert row['passed'], row

    for name, raw in [('short-frame', wire[:31]), ('bad-magic', b'X' + wire[1:]),
            ('reserved', wire[:24] + struct.pack('<Q', 1) + wire[32:]),
            ('wrong-body-size', wire[:16] + struct.pack('<Q', 1) + wire[24:]),
            ('invalid-tool-utf8', query('host_list', b'{}')[:32] + b'\xffost_list{}')]:
        reset()
        observe(name, bridge.enter(raw)[0], INVALID)
    for field in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88):
        reset()
        assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        bridge.word(ACTION + field, bridge.word(ACTION + field) ^ 1)
        observe('action-custody-' + str(field), bridge.enter(wire)[0], INVALID)
    for at in (REQUEST, REQUEST + 8, REQUEST + 16, REQUEST + 24):
        reset()
        assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        raw = bridge.read(at, 1)
        bridge.write(at, bytes([raw[0] ^ 1]))
        observe('child-request-custody-' + str(at - REQUEST), bridge.enter(wire)[0], INVALID)
    reset()
    assert bridge.enter(wire)[0] == CALL
    bridge.complete()
    changed = bytearray(wire);changed[-1] ^= 1
    observe('original-input-custody', bridge.enter(bytes(changed))[0], INVALID)
    for result in (0, CHILD_CAP + 1, INVALID, CAPACITY):
        reset()
        assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        bridge.word(ACTION + 72, result)
        observe('child-code-' + str(result), bridge.enter(wire)[0], CAPACITY if result == CAPACITY else INVALID)
    reset()
    bridge.word(0, int.from_bytes(b'HRSDW001', 'little'))
    bridge.word(16, (1 << 64) - 1)
    observe('exhausted-sequence', bridge.enter(wire)[0], INVALID)
    reset()
    assert bridge.enter(wire)[0] == CALL
    bridge.complete()
    bridge.word(16, (1 << 64) - 1)
    observe('sequence-state-custody', bridge.enter(wire)[0], INVALID)
    reset()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'value-manifest', 'config-elf', 'runtime', 'oracle', 'output'):
        parser.add_argument('--' + name, required=name != 'oracle', type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from result_safe_dto_cases import cases, profiles
    sys.path.insert(0, str(args.runtime.resolve(strict=True) / 'scripts'))
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    report = dict(schema='hepta.safe-dto.actual-comparison.v1', status='FAIL', profiles=[], controls=[], startup_refusals=[],
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False,
        result_storage_qualified=False, public_request_dispatch_qualified=False)
    save = lambda: (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    save()
    started = time.monotonic()
    try:
        with ExitStack() as stack:
            module = stack.enter_context(NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())))
            value = stack.enter_context(NativeModule(args.value_manifest, manifest_sha256=SHA(args.value_manifest.read_bytes())))
            owner = stack.enter_context(module.session(output_capacity=32, workspace_capacity=WORK))
            canonical = stack.enter_context(value.session(output_capacity=CHILD_CAP, workspace_capacity=WORK))
            report['modules'] = dict(owner=module.metadata, value=value.metadata)
            report['config_executable'] = dict(bytes=args.config_elf.stat().st_size, sha256=SHA(args.config_elf.read_bytes()))
            for label, hosts in profiles():
                directory = out / label
                directory.mkdir(mode=0o700)
                state = config = None
                if hosts is not None:
                    state = directory / 'state'
                    config = directory / 'config.json'
                    config.write_bytes(encode(dict(state_dir=str(state), hosts=hosts)))
                    config.chmod(0o600)
                if hosts == {}:
                    _, original_receipt = original(args.oracle, config, [], directory, 'original-startup', startup_refusal=True)
                    _, native_receipt = original(args.config_elf, config, [], directory, 'native-startup', startup_refusal=True)
                    assert not state.exists()
                    report['startup_refusals'].append(dict(name=label, reference=original_receipt,
                        native=native_receipt, state_not_created=True, passed=True))
                    save()
                    continue
                summary, probe_receipt = original(args.oracle, config, [dict(op='summaries')], directory, 'original-summaries')
                if args.oracle is not None:
                    locks_released(state)
                rows = list(cases(summary[0], hosts))
                aliases = list(hosts or {}) + ['missing', 'shared-target', '', 'a\0', 'a ', 'A', '汉']
                rows.extend(dict(op='platform', alias=name) for name in aliases)
                observations, receipt = original(args.oracle, config, rows, directory, 'original-cases')
                if args.oracle is not None:
                    locks_released(state)
                profile = dict(name=label, status='FAIL', reference_receipts=[probe_receipt, receipt],
                    cases=[], native_entries=0, value_calls=0, config_calls=0, typed_cases=0, platform_cases=0)
                report['profiles'].append(profile)
                save()
                native = ConfigChild(args.config_elf, config, state, directory)
                bridge = Bridge(owner, canonical, native, (NativeRejected, NativeCapacityError))
                failed = True
                native_input = (directory / "native-owner.stdin.bin").open("xb")
                native_output = (directory / "native-owner.stdout.bin").open("xb")
                try:
                    for ordinal, (row, expected) in enumerate(zip(rows, observations, strict=True)):
                        if row['op'] == 'platform':
                            alias = row['alias'].encode()
                            reply = native.invoke(b'HRCFGQ01' + struct.pack('<2Q', 10, len(alias)) + alias)
                            magic, status, diagnostic, size = struct.unpack_from('<8s3Q', reply)
                            assert magic == b'HRCFGM01' and size == len(reply) - 32 and status in (0, 1)
                            if status == 0:
                                signature, generation, platform, name_len = struct.unpack_from('<8s3Q', reply, 32)
                                assert signature == b'HRCFPL01' and generation == 1 and name_len == len(alias) and reply[64:] == alias
                                actual = dict(status=0, alias=row['alias'], platform=('linux', 'macos')[platform])
                                assert diagnostic == 0
                            else:
                                actual = dict(status=1, error=reply[32:].decode())
                            profile['platform_cases'] += 1
                            record = dict(ordinal=ordinal, label='platform-' + row['alias'], passed=actual == expected,
                                actual=actual, expected=expected)
                        else:
                            assert expected['label'] == row['label']
                            wire = query(row['tool'], expected['canonical_body'].encode())
                            native_input.write(struct.pack("<Q", len(wire)) + wire)
                            code, raw, children = bridge.run(wire)
                            native_output.write(struct.pack("<2Q", code, len(raw)) + raw)
                            actual = None
                            if code == 32:
                                magic, admitted, kind, reserved = struct.unpack('<8s3Q', raw)
                                assert magic == b'HRSDR001' and admitted in (0, 1) and reserved == 0
                                assert kind == {'host_list': 1, 'effective_config': 2, 'host_health': 3}.get(row['tool'], 0)
                                actual = bool(admitted)
                            record = dict(ordinal=ordinal, label=row['label'], passed=actual == expected['accepted'] and code == 32,
                                expected=expected['accepted'], actual=actual, native_code=code, input_bytes=len(wire),
                                input_sha256=SHA(wire), output_sha256=SHA(raw), children=children)
                            profile['typed_cases'] += 1
                        profile['cases'].append(record)
                        if not record['passed']:
                            (directory / 'mismatch.json').write_bytes(encode(dict(case=row, expected=expected, actual=record)) + b'\n')
                            raise AssertionError(record)
                    if label == 'mixed':
                        good = next(expected for row, expected in zip(rows, observations, strict=True)
                            if row.get('label') == 'summary-canonical-host_list')
                        report['controls'] = private_controls(bridge, query('host_list', good['canonical_body'].encode()))
                    failed = False
                finally:
                    native_input.close();native_output.close()
                    native.close(failed)
                    profile.update(native_process=native.receipt, native_entries=bridge.entries,
                        value_calls=bridge.value_calls, config_calls=bridge.config_calls)
                    save()
                profile['status'] = 'PASS'
                save()
            from result_storage_raw_value import run_native as run_raw_value
            report['raw_value_extension'] = run_raw_value(args.runtime, 'safe_dto', out / 'raw-value',
                args.config_elf, lambda config: Bridge(owner, canonical, config, (NativeRejected, NativeCapacityError)))
        report.update(status='PASS', compared_cases=sum(len(p['cases']) for p in report['profiles']),
            actual_original_cases=sum(len(p['cases']) + 1 for p in report['profiles']) if args.oracle else 0,
            retained_reference_cases=0 if args.oracle else sum(len(p['cases']) + 1 for p in report['profiles']),
            reference_kind='fresh-locked-original' if args.oracle else 'retained-original-fixture',
            typed_cases=sum(p['typed_cases'] for p in report['profiles']), platform_cases=sum(p['platform_cases'] for p in report['profiles']),
            actual_native_entries=sum(p['native_entries'] for p in report['profiles']),
            actual_value_child_calls=sum(p['value_calls'] for p in report['profiles']),
            actual_config_child_calls=sum(p['config_calls'] for p in report['profiles']),
            actual_config_process_requests=sum(p['native_process']['calls'] for p in report['profiles']),
            controls_passed=len(report['controls']), decisions_equal=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error)
        (out / 'failure.txt').write_text(traceback.format_exc())
        raise
    finally:
        save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('profiles', 'controls', 'modules', 'startup_refusals')}, sort_keys=True))


if __name__ == '__main__':
    main()
