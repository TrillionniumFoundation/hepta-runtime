"""Exercise the emitted callable with its optional observer completely disabled."""
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


def frame(command, deadline=0):
    words = [int.from_bytes(b'HAUCTL01', 'little'), command, 0, 0, 1,
             int(deadline != 0), deadline & ((1 << 64) - 1), deadline >> 64, *([0] * 24)]
    return struct.pack('<32Q', *words)


def run(image_path, output):
    identity = source()
    image = read(image_path)
    output.mkdir(parents=True, exist_ok=False)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                          ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    extent = (len(image) + 4095) & ~4095
    mapped = libc.mmap(None, extent, 3, 0x22, -1, 0)
    require(mapped not in (None, ctypes.c_void_p(-1).value), 'map the complete callable')
    ctypes.memmove(mapped, image, len(image))
    require(libc.mprotect(mapped, extent, 5) == 0, 'immutable executable callable mapping')
    entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                            ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t)(mapped)
    kernel = ctypes.create_string_buffer(b'\0' * 64 + b'\xa5' * 16, 80)
    context = ctypes.create_string_buffer(b'\0' * 128 + b'\xa5' * 16, 144)
    pointers = (ctypes.c_uint64 * 18).from_buffer(context)
    pointers[2], pointers[3] = ctypes.addressof(kernel), 64
    rows = []

    def actor():
        return ctypes.create_string_buffer(b'\0' * 512 + b'\xa5' * 16, 528)

    def snapshot(operand, request):
        queue = ctypes.string_at(pointers[4], pointers[5] + 16) if pointers[4] else b''
        return dict(input=request.raw, actor=operand.raw, context=context.raw, kernel=kernel.raw, queue=queue)

    def invoke(name, wire, operand, expected, actor_capacity=512, context_capacity=128):
        require(pointers[7] == pointers[8] == 0, 'there is no observer or foreign effect callback')
        request = ctypes.create_string_buffer(wire + b'\xa5' * 16, len(wire) + 16)
        before = snapshot(operand, request)
        started = time.monotonic_ns()
        returned = entry(request, len(wire), operand, actor_capacity, context, context_capacity)
        finished = time.monotonic_ns()
        after = snapshot(operand, request)
        require(returned == expected, 'actual observer-free result: ' + name)
        require(before['input'] == after['input'], 'complete immutable callable request')
        for key, size in (('actor', 512), ('context', 128), ('kernel', 64)):
            require(after[key][size:] == b'\xa5' * 16, 'complete observer-free guard: ' + key)
        if expected >= 0xfffffffd:
            require(before == after, 'refusal changes no physical byte')
        members = {}
        for phase, buffers in (('before', before), ('after', after)):
            for label, raw in buffers.items():
                key = phase + '-' + label
                filename = name + '.' + key + '.bin'
                (output / filename).write_bytes(raw)
                members[key] = dict(file=filename, **pin(raw))
        rows.append(dict(name=name, returned=returned, request_bytes=len(wire),
                         actor_capacity=actor_capacity, context_capacity=context_capacity,
                         monotonic_before_ns=started, monotonic_after_ns=finished, buffers=members))
        return struct.unpack('<64Q', operand.raw[:512])

    initial = frame(0)
    try:
        for name, wire, expected, ac, cc in (
            ('short', initial[:-1], 0xffffffff, 512, 128),
            ('long', initial + b'\0', 0xffffffff, 512, 128),
            ('magic', b'X' + initial[1:], 0xffffffff, 512, 128),
            ('external-resume', frame(3), 0xffffffff, 512, 128),
            ('command', frame(7), 0xffffffff, 512, 128),
            ('actor-capacity', initial, 0xfffffffe, 511, 128),
            ('context-capacity', initial, 0xfffffffe, 512, 127),
        ):
            invoke(name, wire, actor(), expected, ac, cc)
        pointers[9] = 1
        invoke('context-reserved', initial, actor(), 0xffffffff)
        pointers[9] = 0
        pointers[0] = 1
        invoke('context-state', initial, actor(), 0xfffffffd)
        pointers[0] = 0
        initialize = actor()
        result = invoke('initialize', initial, initialize, 512)
        require(result[:3] == (int.from_bytes(b'HAUCOR01', 'little'), 0, 0), 'actual initialization')
        exclusive = actor()
        result = invoke('exclusive-acquire', frame(1), exclusive, 512)
        require(result[1:3] == (0, 3) and result[12:14] == (1, 1), 'actual exclusive ownership')
        result = invoke('exclusive-drop', frame(5), exclusive, 512)
        require(result[1:3] == (0, 0) and result[12:14] == (0, 0), 'actual exclusive release')
        shared = actor()
        deadline = time.monotonic_ns() + 2_000_000_000
        result = invoke('shared-acquire', frame(2, deadline), shared, 512)
        require(result[1:3] == (0, 3) and result[12:14] == (0, 1), 'actual shared ownership')
        result = invoke('shared-finish', frame(4), shared, 512)
        require(result[1:3] == (0, 0) and result[12:14] == (0, 0), 'actual shared finish')
        invoke('destroy', frame(6), initialize, 0)
        require(all(pointers[index] == 0 for index in (0, 1, 4, 5, 6)), 'native queue mapping retired')
        require(pointers[2] == ctypes.addressof(kernel) and pointers[3] == 64, 'borrowed kernel remains external')
    finally:
        require(libc.munmap(mapped, extent) == 0, 'release the immutable code mapping')
    require(source() == identity, 'observer-free source remains frozen')
    report = dict(schema='hepta.audit-controller-callable.observer-free.v1',
                  source_manifest_sha256=identity, image=pin(image), pid=os.getpid(),
                  native_calls=len(rows), refusals=9, ordinary_calls=6,
                  observer_pointer=0, foreign_effect_calls=0, runtime_rust_required=False,
                  deadline=deadline, calls=rows, public_handler_qualified=False, whole_runtime_replaced=False)
    (output / 'CALLABLE.json').write_bytes(encoded(report))
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.image.resolve(strict=True), args.output.absolute())
