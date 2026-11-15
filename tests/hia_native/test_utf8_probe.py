"""Execute the exact relocated production UTF-8 closure and record both timings."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--composition', type=Path, required=True)
    parser.add_argument('--profiles-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.profiles_dir.resolve(strict=True)))
    from hia_native_loader import NativeModule
    composition = json.loads(args.composition.read_bytes())
    modules, metadata = {}, {}
    for name in ('new', 'original'):
        path = getattr(args, name)
        raw = path.read_bytes()
        document = json.loads(raw)
        assert document['source_sha256'] == composition['variants'][name]['sha256']
        modules[name] = NativeModule(path, manifest_sha256=digest(raw))
        metadata[name] = dict(manifest_sha256=digest(raw), source_sha256=document['source_sha256'],
                              image_sha256=document['image_sha256'])
    sessions = {name: module.session(output_capacity=1, workspace_capacity=0)
                for name, module in modules.items()}
    rows = []
    cases = 0
    complete_inputs, complete_outputs = hashlib.sha256(), hashlib.sha256()
    started = time.monotonic()
    captures = {name: gzip.open(args.output / (name + '.bin.gz'), 'xb', compresslevel=1)
                for name in ('requests', 'new', 'original')}
    try:
        def check(wire):
            nonlocal cases
            try:
                wire.decode('utf-8', 'strict')
                expected = b'\1'
            except UnicodeDecodeError:
                expected = b'\0'
            actual = {name: session.invoke(wire) for name, session in sessions.items()}
            assert actual['new'] == actual['original'] == expected, (wire.hex(), actual, expected.hex())
            captures['requests'].write(len(wire).to_bytes(8, 'little') + wire)
            for name in ('new', 'original'): captures[name].write(actual[name])
            complete_inputs.update(len(wire).to_bytes(8, 'little') + wire)
            complete_outputs.update(expected)
            cases += 1
        check(b'')
        for value in range(256):
            check(bytes([value]))
        for first in range(256):
            for second in range(256):
                check(bytes([first, second]))
        boundaries = [b'\xc0\x80', b'\xc1\xbf', b'\xc2\x80', b'\xdf\xbf',
                      b'\xe0\x9f\xbf', b'\xe0\xa0\x80', b'\xed\x9f\xbf', b'\xed\xa0\x80',
                      b'\xef\xbf\xbf', b'\xf0\x8f\xbf\xbf', b'\xf0\x90\x80\x80',
                      b'\xf4\x8f\xbf\xbf', b'\xf4\x90\x80\x80', b'\xf5\x80\x80\x80',
                      b'\x80', b'\xff', b'\xc2', b'\xe0\xa0', b'\xf0\x90\x80']
        for prefix in range(65):
            for suffix in (0, 1, 31, 32, 33, 64):
                for middle in boundaries:
                    check(b'A' * prefix + middle + b'\0' * suffix)
        rng = random.Random(0x48555446)
        for _ in range(4096):
            check(bytes(rng.randrange(256) for _ in range(rng.randrange(129))))
        for size in (31, 32, 33, 63, 64, 65, 1023, 1024, 1025):
            for value in range(128):
                check(bytes([value]) * size)
        correctness_seconds = time.monotonic() - started
        for size in (1 << 20, 5 << 20, 32 << 20):
            wire = b'A' * size
            for name in ('original', 'new'):
                samples = []
                for _ in range(3):
                    tick = time.monotonic_ns()
                    assert sessions[name].invoke(wire) == b'\1'
                    samples.append(time.monotonic_ns() - tick)
                rows.append(dict(variant=name, bytes=size, samples_ns=samples,
                                 median_ns=sorted(samples)[1], source_sha256=metadata[name]['source_sha256']))
        # The test-only entry has the same explicit no-output-on-capacity admission.
        for module in modules.values():
            code, output, workspace = module.invoke_raw(b'A' * 33, output_capacity=0,
                workspace_capacity=17, output_fill=0xa5, workspace_fill=0x5a)
            assert code == 0xfffffffe and output == b'' and workspace == b'\x5a' * 17
        result = dict(schema='hepta.private.batch-utf8-probe-result.v1', status='PASS',
            compared_inputs=cases, actual_native_calls=cases * 2 + 18 + 2,
            input_sha256=complete_inputs.hexdigest(), expected_sha256=complete_outputs.hexdigest(),
            correctness_seconds=correctness_seconds, seconds=time.monotonic()-started,
            composition_sha256=digest(args.composition.read_bytes()), test_sha256=digest(Path(__file__).read_bytes()),
            exact_same_relocated_production_closure=composition['exact_same_relocated_production_closure'],
            modules=metadata, timing_rows=rows, original_rust_execution=False)
        (args.output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        print(json.dumps(result, sort_keys=True))
    finally:
        for capture in captures.values(): capture.close()
        for session in sessions.values(): session.close()
        for module in modules.values(): module.close()


if __name__ == '__main__': main()
