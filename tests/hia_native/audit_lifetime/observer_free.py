"""Exercise actual lifetime ownership with the optional observer disabled."""
from pathlib import Path
import argparse
import ctypes
import os
import struct
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from common import encoded, pin, read, require, source


def frame(operation, key=b'', pointer=0, generation=1):
    return b'HARGQ001' + struct.pack('<7Q', operation, generation, pointer, len(key), 0, 0, 0) + key + bytes(128)


def word(raw, index):
    return struct.unpack_from('<Q', raw, index * 8)[0]


def change(raw, index, value):
    return raw[:index * 8] + struct.pack('<Q', value) + raw[index * 8 + 8:]


def run(callable_path, refs_path, output):
    identity = source()
    output.mkdir(parents=True, exist_ok=False)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    entry_type = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)
    mappings = []

    def image(path):
        raw = read(path)
        extent = (len(raw) + 4095) & ~4095
        address = libc.mmap(None, extent, 3, 0x22, -1, 0)
        require(address not in (None, ctypes.c_void_p(-1).value), 'complete executable image allocation')
        ctypes.memmove(address, raw, len(raw))
        require(libc.mprotect(address, extent, 5) == 0, 'immutable executable image')
        mappings.append((address, extent))
        return entry_type(address)

    callable_entry, refs_entry = image(callable_path), image(refs_path)
    kernel = ctypes.create_string_buffer(bytes(64) + b'\xa5' * 16, 80)
    context = ctypes.create_string_buffer(bytes(128) + b'\xa5' * 16, 144)
    pointers = (ctypes.c_uint64 * 18).from_buffer(context)
    pointers[2], pointers[3] = ctypes.addressof(kernel), 64
    rows = []

    def actor():
        return ctypes.create_string_buffer(bytes(512) + b'\xa5' * 16, 528)

    def snapshot(operand, request):
        active = ctypes.string_at(pointers[4], pointers[5] + 16) if pointers[4] else b''
        pins = ctypes.string_at(pointers[7], pointers[8] + 16) if pointers[7] else b''
        return dict(input=request.raw, actor=operand.raw, context=context.raw,
                    kernel=kernel.raw, active=active, pins=pins)

    def save(name, kind, before, after, returned, **metadata):
        members = {}
        for phase, buffers in (('before', before), ('after', after)):
            for label, raw in buffers.items():
                key = phase + '-' + label
                filename = name + '.' + key + '.bin'
                (output / filename).write_bytes(raw)
                members[key] = dict(file=filename, **pin(raw))
        rows.append(dict(name=name, kind=kind, returned=returned, buffers=members, **metadata))

    def invoke(name, wire, operand, expected=512, actor_capacity=512, context_capacity=128, result=0):
        require(pointers[10] == pointers[11] == 0, 'observer and foreign callback pointers are zero')
        request = ctypes.create_string_buffer(wire + b'\xa5' * 16, len(wire) + 16)
        before = snapshot(operand, request)
        started = time.monotonic_ns()
        returned = callable_entry(request, len(wire), operand, actor_capacity, context, context_capacity)
        ended = time.monotonic_ns()
        after = snapshot(operand, request)
        save(name, 'callable', before, after, returned, request_bytes=len(wire),
             actor_capacity=actor_capacity, context_capacity=context_capacity,
             monotonic_before_ns=started, monotonic_after_ns=ended, expected_result=result)
        require(returned == expected, 'actual observer-free result: ' + name)
        require(before['input'] == after['input'], 'complete unchanged external input')
        for key, capacity in (('actor', 512), ('context', 128), ('kernel', 64)):
            require(after[key][capacity:] == b'\xa5' * 16, 'complete observer-free guard: ' + key)
        if expected != 512:
            require(before == after, 'complete refusal leaves every physical byte unchanged')
        else:
            require(word(after['actor'], 1) == 0 and word(after['actor'], 2) == result,
                    'actual HIA completed result: ' + name)
        return after

    def reference(name, operation, kind, pointer=0, expected=64, wire=None, capacity=64, workspace=0):
        if wire is None:
            wire = b'HARREF01' + struct.pack('<7Q', operation, kind, pointer, 0, 0, 0, 0)
        request = ctypes.create_string_buffer(wire + b'\xa5' * 16, len(wire) + 16)
        result = ctypes.create_string_buffer(b'\xa5' * 80, 80)
        work = ctypes.create_string_buffer(b'\x5a' * 16, 16)
        before = dict(input=request.raw, output=result.raw, workspace=work.raw)
        returned = refs_entry(request, len(wire), result, capacity, work, workspace)
        after = dict(input=request.raw, output=result.raw, workspace=work.raw)
        save(name, 'reference', before, after, returned, request_bytes=len(wire),
             output_capacity=capacity, workspace_capacity=workspace)
        require(returned == expected, 'actual native reference result: ' + name)
        require(before['input'] == after['input'] and before['workspace'] == after['workspace']
                and after['output'][64:] == b'\xa5' * 16, 'complete reference-owned buffers')
        if expected != 64:
            require(before == after, 'reference refusal has no output changes')
            return None
        return struct.unpack('<8Q', after['output'][:64])

    initial = frame(0)
    try:
        for name, wire, expected, ac, cc in (
            ('short', initial[:-1], 0xffffffff, 512, 128),
            ('long', initial + b'\0', 0xffffffff, 512, 128),
            ('magic', b'X' + initial[1:], 0xffffffff, 512, 128),
            ('operation', change(initial, 1, 9), 0xffffffff, 512, 128),
            ('external-resume', change(initial, 6, 1), 0xffffffff, 512, 128),
            ('generation-zero', change(initial, 2, 0), 0xffffffff, 512, 128),
            ('panic-shape', change(initial, 5, 2), 0xffffffff, 512, 128),
            ('observation-tail', initial[:-1] + b'\1', 0xffffffff, 512, 128),
            ('actor-capacity', initial, 0xfffffffe, 511, 128),
            ('context-capacity', initial, 0xfffffffe, 512, 127),
        ):
            invoke(name, wire, actor(), expected, ac, cc)
        pointers[12] = 1
        invoke('context-reserved', initial, actor(), 0xffffffff)
        pointers[12] = 0
        pointers[0] = 1
        invoke('context-state', initial, actor(), 0xfffffff9)
        pointers[0] = 0
        invoke('initialize', initial, actor())
        invoke('wrong-generation', frame(3, generation=2), actor(), 0xfffffff9)
        invoke('unowned-cohort-insert', frame(7, b'x', 8), actor(), 0xfffffff9)
        invoke('unowned-cohort-release', frame(8), actor(), 0xfffffff9)
        active = reference('marker-new', 0, 1)[3]
        pin_pointer = reference('pin-new', 1, 2)[3]
        valid_ref = b'HARREF01' + struct.pack('<7Q', 8, 1, active, 0, 0, 0, 0)
        for name, wire, expected, capacity, workspace in (
            ('ref-short', valid_ref[:-1], 0xffffffff, 64, 0),
            ('ref-long', valid_ref + b'\0', 0xffffffff, 64, 0),
            ('ref-magic', b'X' + valid_ref[1:], 0xffffffff, 64, 0),
            ('ref-reserved', change(valid_ref, 4, 1), 0xffffffff, 64, 0),
            ('ref-kind', change(valid_ref, 2, 2), 0xfffffff9, 64, 0),
            ('ref-capacity', valid_ref, 0xfffffffe, 63, 0),
            ('ref-workspace', valid_ref, 0xffffffff, 64, 1),
        ):
            reference(name, 8, 1, active, expected, wire, capacity, workspace)
        invoke('publish-active', frame(1, b'owned', active), actor())
        invoke('publish-pin', frame(2, b'owned', pin_pointer), actor())
        invoke('dispatch-true', frame(3, b'owned'), actor(), result=1)
        invoke('any-true', frame(4, b'owned'), actor(), result=1)
        require(reference('marker-finish', 9, 1, active)[7] == 0, 'actual Release false')
        invoke('dispatch-false', frame(3, b'owned'), actor())
        invoke('pinned-after-finish', frame(4, b'owned'), actor(), result=1)
        reference('marker-drop', 3, 1, active)
        reference('pin-drop', 3, 2, pin_pointer)
        invoke('expired-pruned', frame(4, b'owned'), actor())
        cohort = actor()
        invoke('cohort-acquire', frame(6), cohort, result=2)
        remaining = reference('cohort-marker-new', 0, 1)[3]
        invoke('cohort-insert', frame(7, b'cohort', remaining), cohort, result=2)
        invoke('cohort-release', frame(8), cohort)
        invoke('cohort-visible', frame(3, b'cohort'), actor(), result=1)
        disposed = invoke('destroy', frame(5), actor())
        require(all(pointers[i] == 0 for i in (0, 1, 4, 5, 6, 7, 8, 9)), 'both owned maps retired')
        require(not disposed['active'] and not disposed['pins'], 'no owned maps remain')
        require(reference('outliving-marker-load', 8, 1, remaining)[7] == 1, 'strong object outlives both maps')
        require(reference('outliving-marker-drop', 3, 1, remaining)[2] == 2, 'actual last-reference unmap')
    finally:
        for address, extent in mappings:
            require(libc.munmap(address, extent) == 0, 'immutable code mapping released')
    require(source() == identity, 'observer-free source unchanged')
    report = dict(schema='hepta.audit-lifetime.observer-free.v1', source_manifest_sha256=identity,
                  callable=pin(read(callable_path)), references=pin(read(refs_path)), pid=os.getpid(),
                  native_calls=len(rows), refusals=sum(row['returned'] > 0xfffffff0 for row in rows),
                  observer_pointer=0, foreign_effect_calls=0, runtime_rust_required=False, calls=rows,
                  public_handler_qualified=False, whole_runtime_replaced=False)
    (output / 'OBSERVER_FREE.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--callable', type=Path, required=True)
    parser.add_argument('--refs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.callable.resolve(strict=True), args.refs.resolve(strict=True), args.output.absolute())
