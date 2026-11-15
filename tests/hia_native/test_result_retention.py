# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare exact original Records using actual native Value, metadata, DTO and codec children."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import struct
import sys
import time
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
ACTION, REQUEST, REPLY = 256, (160 << 20) + 65536, (176 << 20) + 65536
WORK, CHILD_CAP, OUTPUT = 256 << 20, 64 << 20, 98336
STATES = ('unknown', 'stored', 'overflow', 'not_retained_dto', 'not_completed')


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def request(row, raw):
    tool, identity, owner, policy = (row[key].encode() for key in ('tool', 'request_id', 'owner', 'policy_binding'))
    timestamp = int(row['accepted'])
    return b'HRRTQ001' + struct.pack('<11Q', row['operation'], int(row['body'] is not None),
        timestamp & ((1 << 64) - 1), timestamp >> 64, len(tool), len(identity), len(owner), len(policy),
        len(raw), 0, 0) + tool + identity + owner + policy + raw


class Bridge:
    def __init__(self, owner, value, typed, metadata, dto, codec, exceptions):
        self.owner, self.value, self.typed = owner, value, typed
        self.metadata, self.dto, self.codec, self.exceptions = metadata, dto, codec, exceptions
        self.entries = 0
        self.calls = {key: 0 for key in ('value', 'typed', 'metadata', 'dto', 'codec')}

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
        magic, seq, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = struct.unpack('<8s11Q', self.read(ACTION, 96))
        assert magic == b'HRRTA001' and seq > 0 and 1 <= child <= 5
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and capacity == CHILD_CAP and 24 <= size <= (8 << 20) + 512
        wire = self.read(start, size)
        name = ('value', 'typed', 'metadata', 'dto', 'codec')[child - 1]
        assert wire[:8] == (b'HSJVAL01', b'HRTYP001', b'HRPRQ001', b'HRSDQ001', b'HRCODEC1')[child - 1]
        self.calls[name] += 1
        nested = []
        if child == 3:
            result, reply, nested = self.metadata.run(wire)
        elif child == 4:
            result, reply, nested = self.dto.run(wire)
        else:
            result, reply = self.invoke({1: self.value, 2: self.typed, 5: self.codec}[child], wire)
        self.write(REPLY, reply)
        self.word(ACTION + 64, seq)
        self.word(ACTION + 72, result)
        return dict(sequence=seq, child=child, name=name, input_bytes=len(wire), input_sha256=SHA(wire),
            output_bytes=len(reply), output_sha256=SHA(reply), child_code=result, nested=nested)

    def run(self, wire):
        code, raw = self.enter(wire)
        calls = []
        while code == CALL:
            assert len(calls) < 7
            calls.append(self.complete())
            code, raw = self.enter(wire)
        return code, raw, calls


def controls(bridge, wire, module):
    rows = []

    def reset():
        bridge.write(0, bytes(512))

    def observe(name, actual, expected):
        row = dict(name=name, expected=expected, actual=actual, passed=actual == expected)
        rows.append(row)
        assert row['passed'], row

    def rejected(name, changed):
        reset()
        ctypes.memset(bridge.owner._output, 0x69, OUTPUT)
        observe(name, bridge.enter(changed)[0], INVALID)
        assert ctypes.string_at(bridge.owner._output, OUTPUT) == b'\x69' * OUTPUT
        rows[-1]['output_untouched'] = True

    for name, changed in [('short', wire[:287]), ('magic', b'X' + wire[1:])]:
        rejected(name, changed)
    for offset, value in ((8, 0), (16, 2), (40, 17), (48, 63), (56, 65), (64, 0), (72, 1), (80, 1), (88, 1)):
        changed = bytearray(wire);struct.pack_into('<Q', changed, offset, value)
        rejected('frame-field-' + str(offset), bytes(changed))
    for field in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88):
        reset();assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        bridge.word(ACTION + field, bridge.word(ACTION + field) ^ 1)
        observe('action-custody-' + str(field), bridge.enter(wire)[0], INVALID)
    for offset in (0, 8, 16, 24):
        reset();assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        first = bridge.read(REQUEST + offset, 1)
        bridge.write(REQUEST + offset, bytes([first[0] ^ 1]))
        observe('child-request-custody-' + str(offset), bridge.enter(wire)[0], INVALID)
    reset();assert bridge.enter(wire)[0] == CALL
    bridge.complete()
    changed = bytearray(wire);changed[-1] ^= 1
    observe('caller-input-custody', bridge.enter(bytes(changed))[0], INVALID)
    for value in (0, CHILD_CAP + 1, INVALID, CAPACITY):
        reset();assert bridge.enter(wire)[0] == CALL
        bridge.complete();bridge.word(ACTION + 72, value)
        observe('child-code-' + str(value), bridge.enter(wire)[0], CAPACITY if value == CAPACITY else INVALID)
    reset();bridge.word(0, int.from_bytes(b'HRRTW001', 'little'));bridge.word(16, (1 << 64) - 1)
    observe('exhausted-sequence', bridge.enter(wire)[0], INVALID)
    for phase in range(1, 8):
        reset();assert bridge.enter(wire)[0] == CALL
        for prior in range(1, phase):
            bridge.complete();assert bridge.enter(wire)[0] == CALL
        bridge.complete()
        if phase == 5:
            bridge.word(REPLY + 24, 1)
        else:
            bridge.write(REPLY, b'!')
        observe('invalid-child-reply-phase-' + str(phase), bridge.enter(wire)[0], INVALID)
    reset()
    # The admitted owner already owns a complete guarded workspace. Borrow that
    # allocation with the exact smaller ABI lengths, so capacity controls do not
    # allocate another 256 MiB while all five real children remain alive. The
    # loader still checks the canaries at each declared boundary on every call.
    def borrowed_capacity(output_capacity, workspace_capacity):
        assert 0 <= output_capacity <= bridge.owner.output_capacity
        assert 0 <= workspace_capacity <= bridge.owner.workspace_capacity
        try:
            raw = module._invoke_buffers(wire, bridge.owner._output, bridge.owner._workspace,
                output_capacity, workspace_capacity)
            return len(raw)
        except bridge.exceptions as error:
            return error.code

    for capacity in (0, 31):
        observe('output-capacity-' + str(capacity), borrowed_capacity(capacity, WORK), CAPACITY)
        rows[-1]['existing_guarded_allocation'] = True
    observe('workspace-capacity', borrowed_capacity(OUTPUT, WORK - 1), CAPACITY)
    rows[-1]['existing_guarded_allocation'] = True
    reset()
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'value-manifest', 'typed-manifest', 'metadata-manifest', 'dto-manifest',
                 'codec-manifest', 'config-elf', 'runtime', 'oracle', 'output'):
        parser.add_argument('--' + name, required=name != 'oracle', type=Path)
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path[:0] = [str(Path(__file__).resolve().parent), str(args.runtime.resolve(strict=True) / 'scripts')]
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    from result_storage_mapped_session import MappedSession
    from test_result_safe_dto import ConfigChild, Bridge as DtoBridge, original as original_call, locks_released
    from functools import partial
    original = partial(original_call, domain='retention')
    from test_request_result import Bridge as MetadataBridge
    from result_safe_dto_cases import profiles
    from result_retention_cases import cases, size_probes
    report = dict(schema='hepta.request-retention.actual-comparison.v1', status='FAIL', profiles=[],
        controls=[], startup_refusals=[], whole_runtime_replaced=False, production_activated=False,
        old_stack_removal_qualified=False, result_storage_qualified=False, audit_storage_qualified=False,
        public_request_dispatch_qualified=False, original_descriptor_validation_executed=False)
    save = lambda: (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    save();started = time.monotonic()
    try:
        with ExitStack() as stack:
            def load(path, output, work):
                module = stack.enter_context(NativeModule(path, manifest_sha256=SHA(path.read_bytes())))
                session = stack.enter_context(MappedSession(module, output_capacity=output, workspace_capacity=work))
                return module, session
            owner_module, owner = load(args.manifest, OUTPUT, WORK)
            value_module, value = load(args.value_manifest, CHILD_CAP, WORK)
            typed_module, typed = load(args.typed_manifest, 16 << 20, 96 << 20)
            metadata_module, metadata = load(args.metadata_manifest, 16 << 20, 192 << 20)
            dto_module, dto = load(args.dto_manifest, 32, WORK)
            codec_module, codec = load(args.codec_manifest, 1 << 20, 1 << 20)
            report['modules'] = {key: module.metadata for key, module in
                [('owner', owner_module), ('value', value_module), ('typed', typed_module),
                 ('metadata', metadata_module), ('dto', dto_module), ('codec', codec_module)]}
            report['native_workspace_allocation'] = 'private anonymous demand-zero; unchanged qualified invocation and guards'
            report['config_executable'] = dict(bytes=args.config_elf.stat().st_size, sha256=SHA(args.config_elf.read_bytes()))
            for label, hosts in profiles():
                directory = out / label;directory.mkdir(mode=0o700)
                state = config = None
                if hosts is not None:
                    state = directory / 'state';config = directory / 'config.json'
                    config.write_bytes(encode(dict(state_dir=str(state), hosts=hosts)));config.chmod(0o600)
                if hosts == {}:
                    _, old = original(args.oracle, config, [], directory, 'original-startup', startup_refusal=True)
                    _, new = original(args.config_elf, config, [], directory, 'native-startup', startup_refusal=True)
                    assert not state.exists()
                    report['startup_refusals'].append(dict(name=label, reference=old, native=new, state_not_created=True))
                    save();continue
                summary, summary_receipt = original(args.oracle, config, [dict(op='summaries')], directory, 'original-summaries')
                if args.oracle is not None:
                    locks_released(state)
                probes, probe_receipt = original(args.oracle, config, list(size_probes()), directory, 'original-size-probes')
                if args.oracle is not None:
                    locks_released(state)
                rows = list(cases(label, summary[0], hosts, probes))
                observations, original_receipt = original(args.oracle, config, rows, directory, 'original-cases')
                if args.oracle is not None:
                    locks_released(state)
                profile = dict(name=label, status='FAIL', reference_receipts=[summary_receipt, probe_receipt, original_receipt],
                    cases=[], states={name: 0 for name in STATES})
                report['profiles'].append(profile);save()
                native = ConfigChild(args.config_elf, config, state, directory)
                errors = (NativeRejected, NativeCapacityError)
                metadata_bridge = MetadataBridge(metadata, value, typed, errors)
                dto_bridge = DtoBridge(dto, value, native, errors)
                bridge = Bridge(owner, value, typed, metadata_bridge, dto_bridge, codec, errors)
                failed = True
                native_input = (directory / 'native-owner.stdin.bin').open('xb')
                native_output = (directory / 'native-owner.stdout.bin').open('xb')
                try:
                    for ordinal, (row, expected) in enumerate(zip(rows, observations, strict=True)):
                        assert row['label'] == expected['label']
                        body = expected['canonical_body'].encode()
                        if row['label'] == 'canonical-body-exactly-8MiB':
                            assert len(body) == 8 << 20, len(body)
                        wire = request(row, body)
                        native_input.write(struct.pack('<Q', len(wire)) + wire)
                        code, raw, children = bridge.run(wire)
                        native_output.write(struct.pack('<Q', len(raw)) + raw)
                        actual_state = actual_record = None
                        payload_size = 0
                        if 32 <= code <= OUTPUT:
                            magic, number, size, payload_size = struct.unpack_from('<8s3Q', raw)
                            assert magic == b'HRRTR001' and number < len(STATES) and size == len(raw) - 32
                            actual_state, actual_record = STATES[number], raw[32:]
                        expected_record = expected['record_json'].encode()
                        expected_payload = json.loads(expected_record)['payload_bytes'] or 0
                        passed = actual_state == expected['state'] and actual_record == expected_record and payload_size == expected_payload
                        record = dict(ordinal=ordinal, label=row['label'], passed=passed, expected_state=expected['state'],
                            actual_state=actual_state, native_code=code, input_bytes=len(wire), input_sha256=SHA(wire),
                            expected_record_sha256=SHA(expected_record), actual_record_sha256=SHA(actual_record or b''),
                            output_sha256=SHA(raw), payload_bytes=payload_size, typed_bytes=expected['typed_bytes'],
                            preview_bytes=expected['preview_bytes'], children=children)
                        profile['cases'].append(record)
                        if not passed:
                            (directory / 'mismatch.json').write_bytes(encode(dict(case=row, expected=expected,
                                actual_record=actual_record.decode() if actual_record else None, actual=record)) + b'\n')
                            raise AssertionError(record)
                        profile['states'][actual_state] += 1
                    if label == 'mixed':
                        pair = next((row, expected) for row, expected in zip(rows, observations, strict=True)
                            if row['label'] == 'dto-summary-canonical-host_list')
                        report['controls'] = controls(bridge, request(pair[0], pair[1]['canonical_body'].encode()), owner_module)
                    failed = False
                finally:
                    native_input.close();native_output.close();native.close(failed)
                    profile.update(native_process=native.receipt, native_entries=bridge.entries, child_calls=bridge.calls,
                        metadata_entries=metadata_bridge.entries, metadata_value_calls=metadata_bridge.value_calls,
                        metadata_typed_calls=metadata_bridge.typed_calls, dto_entries=dto_bridge.entries,
                        dto_value_calls=dto_bridge.value_calls, config_calls=dto_bridge.config_calls)
                    save()
                profile['status'] = 'PASS';save()
        report.update(status='PASS', compared_cases=sum(len(p['cases']) for p in report['profiles']),
            actual_original_cases=sum(len(p['cases']) + 7 for p in report['profiles']) if args.oracle else 0,
            retained_reference_cases=0 if args.oracle else sum(len(p['cases']) + 7 for p in report['profiles']),
            reference_kind='fresh-locked-original' if args.oracle else 'retained-original-fixture',
            actual_native_entries=sum(p['native_entries'] + p['metadata_entries'] + p['dto_entries'] for p in report['profiles']),
            actual_config_process_requests=sum(p['native_process']['calls'] for p in report['profiles']),
            states={name: sum(p['states'][name] for p in report['profiles']) for name in STATES},
            controls_passed=len(report['controls']), exact_record_bytes_equal=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('profiles', 'controls', 'modules', 'startup_refusals')}, sort_keys=True))


if __name__ == '__main__':
    main()
