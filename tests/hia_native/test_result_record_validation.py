# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute original record checks against native typed JSON, Base64 and SHA256."""
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
WORK, OUTPUT, CHILD_CAPACITY = 4 << 20, 256 << 10, 1 << 20
ACTION, REQUEST, REPLY = 256, (1 << 20) + 65536, (2 << 20) + 65536


class Bridge:
    def __init__(self, owner, json_module, codec, errors):
        self.owner, self.json, self.codec, self.errors = owner, json_module, codec, errors
        self.entries = 0
        self.children = {'typed_json': 0, 'binary_codec': 0}

    def read(self, offset, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + offset, size)

    def write(self, offset, raw):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + offset, raw, len(raw))

    def word(self, offset, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + offset)
        if value is None:
            return cell.value
        cell.value = value

    def invoke(self, target, wire):
        try:
            raw = target.invoke(wire)
            return len(raw), raw
        except self.errors as error:
            return error.code, b''

    def enter(self, wire):
        self.entries += 1
        return self.invoke(self.owner, wire)

    def complete(self):
        magic, sequence, child, reserved, start, count, output, capacity, ack, code, zero, zero2 = struct.unpack('<8s11Q', self.read(ACTION, 96))
        assert magic == b'HRVLA001' and sequence > 0 and child in (1, 2)
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and capacity == CHILD_CAPACITY and 24 <= count <= 98328
        wire = self.read(start, count)
        assert wire[:8] == (b'HRSTQ001' if child == 1 else b'HRCODEC1')
        name = 'typed_json' if child == 1 else 'binary_codec'
        self.children[name] += 1
        result, reply = self.invoke(self.json if child == 1 else self.codec, wire)
        self.write(REPLY, reply)
        self.word(ACTION + 64, sequence)
        self.word(ACTION + 72, result)
        return dict(child=name, sequence=sequence, code=result, input_bytes=len(wire), input_sha256=SHA(wire),
            output_bytes=len(reply), output_sha256=SHA(reply))

    def run(self, wire):
        code, raw = self.enter(wire);children = []
        while code == CALL:
            assert len(children) < 3
            children.append(self.complete());code, raw = self.enter(wire)
        return code, raw, children


def controls(bridge, wire, owner_module):
    rows = []

    def reset():
        bridge.write(0, bytes(512))

    def observe(name, expected, actual):
        row = dict(name=name, expected=expected, actual=actual, passed=actual == expected)
        rows.append(row);assert row['passed'], row

    def unchanged(name, changed):
        reset();ctypes.memset(bridge.owner._output, 0x69, OUTPUT)
        observe(name, INVALID, bridge.enter(changed)[0])
        assert ctypes.string_at(bridge.owner._output, OUTPUT) == b'\x69' * OUTPUT
        rows[-1]['output_untouched'] = True

    for name, changed in [('short', wire[:23]), ('magic', b'X' + wire[1:]), ('over-frame-bound', wire + b' ' * (1 << 20))]:
        unchanged(name, changed)
    for offset, value in ((8, len(wire)), (16, 0), (16, (1 << 64) - 1)):
        changed = bytearray(wire);struct.pack_into('<Q', changed, offset, value)
        unchanged('frame-length-' + str(offset) + '-' + str(value), bytes(changed))
    for field in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88):
        reset();assert bridge.enter(wire)[0] == CALL
        bridge.complete();bridge.word(ACTION + field, bridge.word(ACTION + field) ^ 1)
        observe('action-custody-' + str(field), INVALID, bridge.enter(wire)[0])
    for offset in (0, 8, 16, 24):
        reset();assert bridge.enter(wire)[0] == CALL;bridge.complete()
        raw = bridge.read(REQUEST + offset, 1);bridge.write(REQUEST + offset, bytes([raw[0] ^ 1]))
        observe('child-request-custody-' + str(offset), INVALID, bridge.enter(wire)[0])
    reset();assert bridge.enter(wire)[0] == CALL;bridge.complete()
    changed = bytearray(wire);changed[-1] ^= 1
    observe('input-custody', INVALID, bridge.enter(bytes(changed))[0])
    for value in (0, 255, CHILD_CAPACITY + 1, CAPACITY):
        reset();assert bridge.enter(wire)[0] == CALL;bridge.complete();bridge.word(ACTION + 72, value)
        observe('child-code-' + str(value), CAPACITY if value == CAPACITY else INVALID, bridge.enter(wire)[0])
    for offset, value in ((0, 0), (8, 2), (16, 8), (40, 5), (56, 1), (64, 257), (72, (1 << 64) - 1), (160, 1)):
        reset();assert bridge.enter(wire)[0] == CALL;bridge.complete();bridge.word(REPLY + offset, value)
        observe('typed-projection-' + str(offset), INVALID, bridge.enter(wire)[0])
    reset();bridge.word(0, int.from_bytes(b'HRRCW001', 'little'));bridge.word(16, (1 << 64) - 1)
    observe('sequence-exhaustion', INVALID, bridge.enter(wire)[0])
    for phase in (1, 2, 3):
        reset();assert bridge.enter(wire)[0] == CALL
        for _ in range(1, phase):
            bridge.complete();assert bridge.enter(wire)[0] == CALL
        bridge.complete();bridge.word(ACTION + 72, CAPACITY)
        observe('capacity-phase-' + str(phase), CAPACITY, bridge.enter(wire)[0])
    reset();assert bridge.enter(wire)[0] == CALL
    for _ in range(2):
        bridge.complete();assert bridge.enter(wire)[0] == CALL
    bridge.complete();bridge.write(REPLY, b'!')
    observe('digest-child-invalid-alphabet', INVALID, bridge.enter(wire)[0])
    for capacity in (0, 31):
        with owner_module.session(output_capacity=capacity, workspace_capacity=WORK) as small:
            observe('early-output-capacity-' + str(capacity), CAPACITY, bridge.invoke(small, wire)[0])
            bridge.entries += 1
    with owner_module.session(output_capacity=OUTPUT, workspace_capacity=WORK - 1) as small:
        observe('workspace-capacity', CAPACITY, bridge.invoke(small, wire)[0])
        bridge.entries += 1
    reset();code, exact, _ = bridge.run(wire);assert code == len(exact)
    for capacity in (32, len(exact) - 1, len(exact)):
        with owner_module.session(output_capacity=capacity, workspace_capacity=WORK) as small:
            child = Bridge(small, bridge.json, bridge.codec, bridge.errors)
            ctypes.memset(small._output, 0x69, capacity)
            code, raw, _ = child.run(wire)
            observe('final-output-capacity-' + str(capacity), CAPACITY if capacity < len(exact) else len(exact), code)
            assert raw == (b'' if code == CAPACITY else exact)
            if code == CAPACITY:
                assert ctypes.string_at(small._output, capacity) == b'\x69' * capacity
            bridge.entries += child.entries
            for key, count in child.children.items():bridge.children[key] += count
    reset();return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'json-manifest', 'codec-manifest', 'runtime', 'oracle', 'output'):
        parser.add_argument('--' + name, required=name != 'oracle', type=Path)
    args = parser.parse_args()
    out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path[:0] = [str(Path(__file__).resolve().parent), str(args.runtime.resolve(strict=True) / 'scripts')]
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    from test_result_storage_json import process
    from result_record_validation_cases import cases, frame, encoded, record
    report = dict(schema='hepta.request-record.actual-validation.v1', status='FAIL', cases=[], controls=[],
        whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False,
        exact_serde_diagnostics_qualified=False, result_storage_qualified=False,
        original_descriptor_validation_executed=False, original_storage_publication_executed=False)
    save = lambda: (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    save();started = time.monotonic()
    try:
        rows = list(cases())
        data = b''.join(wire.hex().encode() + b'\n' for _, wire in rows)
        if args.oracle is None:
            from result_storage_fixture import retained_bytes
            original, receipt = retained_bytes('record_validation', '', data, out, 'original', suffix='')
            report['retained_reference'] = receipt
        else:
            original, receipt = process([args.oracle], data, out, 'original')
            report['original_process'] = receipt
        replies = original.splitlines();assert len(replies) == len(rows)
        with ExitStack() as stack:
            def load(path, output, work):
                module = stack.enter_context(NativeModule(path, manifest_sha256=SHA(path.read_bytes())))
                return module, stack.enter_context(module.session(output_capacity=output, workspace_capacity=work))
            owner_module, owner = load(args.manifest, OUTPUT, WORK)
            json_module, native_json = load(args.json_manifest, CHILD_CAPACITY, CHILD_CAPACITY)
            codec_module, codec = load(args.codec_manifest, CHILD_CAPACITY, CHILD_CAPACITY)
            report['modules'] = {name: module.metadata for name, module in [('owner', owner_module), ('typed_json', json_module), ('binary_codec', codec_module)]}
            bridge = Bridge(owner, native_json, codec, (NativeRejected, NativeCapacityError))
            diagnostics = {str(i): 0 for i in range(9)}
            with (out / 'native.stdout').open('xb') as sink:
                for ordinal, ((label, wire), expected) in enumerate(zip(rows, replies, strict=True)):
                    code, raw, children = bridge.run(wire)
                    actual = f'{code:08x}:'.encode() + raw.hex().encode()
                    sink.write(actual + b'\n')
                    diagnostic = struct.unpack_from('<Q', raw, 8)[0] if len(raw) >= 32 else None
                    row = dict(ordinal=ordinal, label=label, code=code, diagnostic=diagnostic,
                        input_bytes=len(wire), input_sha256=SHA(wire), output_bytes=len(raw), output_sha256=SHA(raw),
                        expected_sha256=SHA(expected), children=children, passed=actual == expected)
                    report['cases'].append(row)
                    if not row['passed']:
                        (out / 'mismatch.json').write_text(json.dumps(dict(row=row, input_hex=wire.hex(), expected=expected.decode(), actual=actual.decode()), sort_keys=True, indent=2) + '\n')
                        raise AssertionError(row)
                    diagnostics[str(diagnostic)] += 1
            assert (out / 'native.stdout').read_bytes() == original
            report['controls'] = controls(bridge, frame(encoded(record())), owner_module)
            report.update(status='PASS', compared_cases=len(rows), actual_original_requests=len(rows) if args.oracle else 0,
            retained_reference_cases=0 if args.oracle else len(rows),
            reference_kind='fresh-locked-original' if args.oracle else 'retained-original-fixture',
                controls_passed=len(report['controls']), actual_owner_entries=bridge.entries,
                actual_children=bridge.children, exact_projection_payload_and_refusal_class_equal=True,
                diagnostics=diagnostics, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:
        save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'controls', 'modules', 'original_process')}, sort_keys=True))


if __name__ == '__main__':
    main()
