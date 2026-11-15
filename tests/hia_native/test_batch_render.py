"""Execute actual HIA batch diff bytes and retain complete original replay inputs."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import random
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import batch_render_reference as reference


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases(apply):
    contents = [b'', b'x', b'\n', b'x\n', b'a\nb', b'a\nb\nc', b'a\nb\nc\nd',
                b'\r', b'\r\n', b'a\r\r\nb\r', '😀\n漢\r\n\x00\n\u2028'.encode()]
    originals = [b'', b'\n', b'a', b'a\n', b'a\r\n', b'\r\r\n', b'a\nb\nc\nd\ne\nf\n',
                 b'\r\nx\r\r\ny\r', 'α\nβ\n😀\n\x00\n'.encode()]
    for raw in originals:
        owner = apply.Editable(raw)
        count = len(owner.lines)
        for content in contents:
            for anchor in range(count + 1):
                ops = [(1, anchor, 0, content or b'\n')]
                if apply.guards(raw, ops) is None:
                    yield 'single_insert', owner.normalized(), apply.original_apply(raw, ops).normalized(), ops
            for first in range(1, count + 1):
                for last in range(first, count + 1):
                    ops = [(2, first, last, content)]
                    if apply.guards(raw, ops) is None:
                        yield 'single_replace', owner.normalized(), apply.original_apply(raw, ops).normalized(), ops
    rng = random.Random(0x4244494646)
    alphabet = ['a', 'b', 'é', '😀', '漢', '\r', '\x00', '\u0301', '\u2028', '}', ';']
    accepted = 0
    while accepted < 6000:
        values = [''.join(rng.choice(alphabet) for _ in range(rng.randrange(8))).encode()
                  for _ in range(rng.randrange(1, 20))]
        raw = b'\n'.join(values) + (b'\n' if rng.randrange(2) else b'')
        owner = apply.Editable(raw)
        n = len(owner.lines)
        ops = []
        for _ in range(rng.randrange(1, 8)):
            kind = 1 if not n or rng.randrange(2) else 2
            first = rng.randrange(n + 1) if kind == 1 else rng.randrange(1, n + 1)
            last = 0 if kind == 1 else rng.randrange(first, n + 1)
            content = b'\n'.join(''.join(rng.choice(alphabet) for _ in range(rng.randrange(6))).encode()
                                 for _ in range(rng.randrange(8)))
            if kind == 1 and not content:
                content = b'\n'
            ops.append((kind, first, last, content))
        if apply.guards(raw, ops) is not None:
            continue
        accepted += 1
        yield 'random_original_success', owner.normalized(), apply.original_apply(raw, ops).normalized(), ops
    raw = b''.join(f'original-{i}\n'.encode() for i in range(100))
    for contents_count in (0, 1, 2, 3, 4, 9):
        ops = [(2, i*2+1, i*2+1, b'\n'.join(f'added-{i}-{j}'.encode() for j in range(contents_count)))
               for i in range(50)]
        rng.shuffle(ops)
        yield 'fifty_operations', raw, apply.original_apply(raw, ops).normalized(), ops
    # Equal end groups, stable equal starts, zero aggregate deltas, anchor zero.
    for ops in [
        [(1, 0, 0, b'head\n'), (2, 2, 3, b'one'), (1, 3, 0, b'back')],
        [(2, 2, 2, b'one\ntwo'), (1, 2, 0, b'three')],
        [(1, 2, 0, b'three'), (2, 2, 2, b'one\ntwo')],
        [(2, 1, 2, b''), (1, 2, 0, b'one\ntwo'), (2, 6, 7, b'last')],
    ]:
        assert apply.guards(raw, ops) is None
        yield 'ordered_regions', raw, apply.original_apply(raw, ops).normalized(), ops
    big = b'x' * (5 << 20)
    for raw, ops, label in [
        (big, [(2, 1, 1, b'y')], 'five_mib_removed_line'),
        (b'a\nb\nc\n', [(2, 2, 2, big)], 'five_mib_added_line'),
        (big + b'\nb\nc\n', [(1, 1, 0, b'x\ny\nz\nw')], 'five_mib_context_line'),
        (b'\n' * (5 << 20), [(2, 5242880, 5242880, b'last')], 'five_mib_empty_lines'),
        (b'\n' * (5 << 20), [(1, 0, 0, b'\n'), (1, 5242880, 0, b'last')], 'five_mib_empty_boundaries'),
    ]:
        # These cases avoid a Python per-line owner model for the empty-line domain.
        if label == 'five_mib_empty_lines':
            new = raw[:-1] + b'last\n'
        elif label == 'five_mib_empty_boundaries':
            new = b'\n' + raw + b'last\n'
        else:
            new = apply.original_apply(raw, ops).normalized()
        yield label, raw, new, ops


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profiles-dir', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = args.reference.resolve(strict=True)
    sys.path.insert(0, str(runtime / 'scripts'))
    from hia_native_loader import NativeModule
    if args.profiles_dir is not None:
        spec = importlib.util.spec_from_file_location('_render_private_loader', args.profiles_dir / 'hia_native_loader.py')
        private_loader = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = private_loader
        spec.loader.exec_module(private_loader)
        NativeModule = private_loader.NativeModule
    apply = reference.load_apply(runtime)
    raw_manifest = args.manifest.read_bytes()
    manifest = json.loads(raw_manifest)
    rows = []
    input_digest, output_digest = hashlib.sha256(), hashlib.sha256()
    input_size = output_size = 0
    start = time.monotonic()
    controls = []
    with NativeModule(args.manifest, manifest_sha256=sha(raw_manifest)) as module:
        with module.session(output_capacity=1 << 16, workspace_capacity=32768) as small:
            with gzip.open(args.output / 'requests.gz', 'wb', compresslevel=1) as requests, \
                 gzip.open(args.output / 'native-output.gz', 'wb', compresslevel=1) as responses:
                for label, old, new, operations in cases(apply):
                    wire = reference.packet(old, new, operations)
                    expected = reference.response(old, new, operations)
                    started = time.monotonic()
                    if len(expected) <= (1 << 16):
                        actual = small.invoke(wire)
                    else:
                        actual = module.invoke(wire, output_capacity=len(expected), workspace_capacity=32768)
                    assert actual == expected, (label, len(rows), actual[:600], expected[:600])
                    for data, handle, digest in [(struct.pack('<Q', len(wire)) + wire, requests, input_digest),
                                                 (struct.pack('<Q', len(actual)) + actual, responses, output_digest)]:
                        handle.write(data)
                        digest.update(data)
                    input_size += 8 + len(wire)
                    output_size += 8 + len(actual)
                    rows.append({'ordinal': len(rows), 'domain': label, 'input_bytes': len(wire),
                                 'input_sha256': sha(wire), 'output_bytes': len(actual),
                                 'output_sha256': sha(actual), 'seconds': time.monotonic() - started})
        fixture = reference.packet(b'a\nb\nc\n', b'a\nx\ny\nz\nw\nc\n', [(2, 2, 2, b'x\ny\nz\nw')])
        expected = reference.response(b'a\nb\nc\n', b'a\nx\ny\nz\nw\nc\n', [(2, 2, 2, b'x\ny\nz\nw')])
        malformed = [fixture[:i] for i in range(len(fixture))]
        for at, value in [(0, 0), (32, 1), (40, 1), (48, 1), (56, 1), (8, (1<<64)-1),
                          (16, (1<<64)-1), (24, (1<<64)-1), (64, 255)]:
            raw = bytearray(fixture)
            raw[at:at+8] = struct.pack('<Q', value)
            malformed.append(bytes(raw))
        malformed.append(fixture + b'\0')
        plan = 64 + len(b'a\nb\nc\n') + len(b'a\nx\ny\nz\nw\nc\n')
        for at, value in [(plan + 8, 1), (plan + 16, 0), (plan + 16, 51), (plan + 32, 1),
                          (plan + 40, 1), (plan + 48, 1), (plan + 56, 3), (plan + 64, 1),
                          (plan + 72, 0), (plan + 80, 99), (plan + 88, (1<<64)-1)]:
            raw = bytearray(fixture); raw[at:at+8] = struct.pack('<Q', value); malformed.append(bytes(raw))
        for wire in malformed:
            code, output, work = module.invoke_raw(wire, output_capacity=1024, workspace_capacity=32768+17,
                                                   output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xffffffff and output == b'\xa5' * len(output)
            assert work[:32768] == bytes(32768) and work[32768:] == b'\x5a' * 17
            controls.append({'kind': 'invalid', 'input_sha256': sha(wire), 'code': code})
        for capacity in (0, 1, 31, len(expected)-1, len(expected), len(expected)+9):
            code, output, work = module.invoke_raw(fixture, output_capacity=capacity, workspace_capacity=32768+17,
                                                   output_fill=0xa5, workspace_fill=0x5a)
            if capacity < len(expected):
                assert code == 0xfffffffe and output == b'\xa5' * capacity
            else:
                assert code == len(expected) and output[:code] == expected and output[code:] == b'\xa5'*(capacity-code)
            assert work[:32768] == bytes(32768) and work[32768:] == b'\x5a'*17
            controls.append({'kind': 'output_capacity', 'capacity': capacity, 'code': code})
        for capacity in (0, 32767):
            code, output, work = module.invoke_raw(fixture, output_capacity=1024, workspace_capacity=capacity,
                                                   output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xfffffffe and output == b'\xa5'*1024 and work == b'\x5a'*capacity
            controls.append({'kind': 'workspace_capacity', 'capacity': capacity, 'code': code})
    result = {'schema': 'hepta.runtime.batch-render-native.v1', 'status': 'PASS',
        'cases': len(rows), 'controls': len(controls), 'native_calls': len(rows)+len(controls),
        'seconds': time.monotonic()-start, 'manifest_sha256': sha(raw_manifest),
        'source_sha256': manifest['source_sha256'], 'image_sha256': manifest['image_sha256'],
        'requests_sha256': input_digest.hexdigest(), 'requests_bytes': input_size,
        'native_output_sha256': output_digest.hexdigest(), 'native_output_bytes': output_size,
        'production_activated': False, 'whole_runtime_replaced': False}
    (args.output / 'cases.json').write_text(json.dumps(rows, sort_keys=True, indent=2)+'\n')
    (args.output / 'controls.json').write_text(json.dumps(controls, sort_keys=True, indent=2)+'\n')
    (args.output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
