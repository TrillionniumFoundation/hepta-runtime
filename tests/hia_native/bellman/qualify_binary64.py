"""Bitwise hardware comparison of the actual integer-only HIA machine image."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import struct
import sys
import time

def bits(x):
    return struct.unpack('<Q', struct.pack('<d', x))[0]

def value(x):
    return struct.unpack('<d', struct.pack('<Q', x))[0]

def cases():
    edge = [0, 1, 2, 3, (1 << 52)-1, 1 << 52, (1 << 52)+1,
            0x3fefffffffffffff, 0x3ff0000000000000, 0x3ff0000000000001,
            0x7fefffffffffffff, bits(2.0**-53), bits(2.0**-52), bits(0.5), bits(2.0)]
    edge += [x | (1 << 63) for x in edge]
    pairs = [(a, b) for a in edge for b in edge]
    rng = random.Random(6780)
    for exponent in range(2047):
        # Boundaries and exact/near cancellation across every finite exponent.
        a = (exponent << 52) | rng.getrandbits(52)
        pairs.extend([(a, a), (a, a ^ (1 << 63)), (a, (a ^ (1 << 63)) + 1),
                      (a, bits(0.5)), (a, bits(2.0)), (a, bits(1.0))])
    for _ in range(20000):
        a, b = rng.getrandbits(64), rng.getrandbits(64)
        if ((a >> 52) & 2047) != 2047 and ((b >> 52) & 2047) != 2047:
            pairs.append((a, b))
    for operation in range(5):
        for a, b in pairs:
            x, y = value(a), value(b)
            if operation == 0: expected = bits(x + y)
            elif operation == 1: expected = bits(x - y)
            elif operation == 2: expected = bits(x * y)
            elif operation == 3:
                if y == 0:
                    expected = 0x7ff8000000000000 if x == 0 else ((a ^ b) & (1 << 63)) | 0x7ff0000000000000
                else: expected = bits(x / y)
            else: expected = 0 if x == y else 1 if x < y else 2
            yield operation, a, b, expected

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.runtime / 'scripts'))
    from hia_native_loader import NativeModule
    raw = args.manifest.read_bytes()
    module = NativeModule(args.manifest, manifest_sha256=hashlib.sha256(raw).hexdigest())
    args.output.mkdir()
    start = time.monotonic()
    counts = [0] * 5
    with (args.output / 'inputs.bin').open('xb') as inputs, \
         (args.output / 'native.bin').open('xb') as native, \
         (args.output / 'reference.bin').open('xb') as reference, \
         module.session(output_capacity=8, workspace_capacity=1) as session:
        for operation, a, b, expected in cases():
            wire = struct.pack('<QQQ', operation, a, b)
            answer = session.invoke(wire)
            inputs.write(wire)
            native.write(answer)
            reference.write(struct.pack('<Q', expected))
            actual, = struct.unpack('<Q', answer)
            if actual != expected:
                raise AssertionError((operation, hex(a), hex(b), hex(actual), hex(expected)))
            counts[operation] += 1
    # Parameter refusals must not write either borrowed mutable buffer.
    controls = 0
    for wire in [b'', b'\0' * 23, b'\0' * 25, struct.pack('<QQQ', 5, 0, 0),
                 struct.pack('<QQQ', 0, 0x7ff0000000000000, 0),
                 struct.pack('<QQQ', 2, 0, 0xfff8000000000001)]:
        status, out, work = module.invoke_raw(wire, output_capacity=8, workspace_capacity=1,
                                             output_fill=0xa5, workspace_fill=0x5a)
        assert status == 0xffffffff and out == b'\xa5' * 8 and work == b'\x5a'
        controls += 1
    status, out, work = module.invoke_raw(struct.pack('<QQQ', 0, 0, 0), output_capacity=7,
                                         workspace_capacity=1, output_fill=0xa5, workspace_fill=0x5a)
    assert status == 0xfffffffd and out == b'\xa5' * 7 and work == b'\x5a'
    controls += 1
    report = {'status':'PASS', 'operations':['add','subtract','multiply','divide','compare'],
              'counts':counts, 'total':sum(counts), 'parameter_controls':controls,
              'wall_seconds':time.monotonic()-start,
              'scope':'finite input binary64, nearest ties-even; canonical quiet NaN for zero/zero; no general NaN propagation',
              'implementation':'actual HIA-compiled integer-only machine image',
              'reference':'independent CPython hardware binary64 arithmetic; not a Rust original replay',
              'manifest_sha256':hashlib.sha256(raw).hexdigest(),
              'files':{p.name:{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                       for p in args.output.iterdir()}}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))

if __name__ == '__main__':
    main()
