"""Actual flat HIA calls; retain every byte of all three physical buffers."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(ROOT / 'scripts')]
from common import encoded, pin, read, require
from hia_native_loader import NativeModule


def run(manifest, output):
    output.mkdir(parents=True, exist_ok=False)
    count, logical_bytes = 0, 8
    stdout = sys.stdout.buffer
    report = dict(schema='hepta.audit-json.actual-native-process.v1', status='INCOMPLETE',
                  calls=0, native_image=pin(read(manifest.parent / 'module.image.bin')),
                  semantic_host_fallback=False, observed_buffers_complete=True)
    try:
        with (output / 'buffers.bin.gz').open('xb') as physical:
            with gzip.GzipFile(filename='', mode='wb', fileobj=physical, mtime=0, compresslevel=6) as journal:
                journal.write(b'HAJLOG01')
                with NativeModule(manifest, manifest_sha256=pin(read(manifest))['sha256']) as module:
                    for line in sys.stdin.buffer:
                        capacity_text, work_text, hex_text = line.rstrip(b'\n').split(b' ')
                        capacity, work = int(capacity_text), int(work_text)
                        wire = bytes.fromhex(hex_text.decode('ascii'))
                        require(len(wire) <= module.metadata['input_capacity']
                                and capacity <= module.metadata['output_capacity']
                                and work <= module.metadata['workspace_capacity'], 'frozen case fits declared native capacities')
                        before = [wire + b'\xc3'*16, b'\x69'*capacity + b'\xa5'*16,
                                  b'\xa7'*work + b'\x5a'*16]
                        source = ctypes.create_string_buffer(before[0], len(before[0]))
                        result = ctypes.create_string_buffer(before[1], len(before[1]))
                        workspace = ctypes.create_string_buffer(before[2], len(before[2]))
                        code = module._entry(source, len(wire), result, capacity, workspace, work)
                        after = [source.raw, result.raw, workspace.raw]
                        header = b'HAJCAL01' + struct.pack('<5Q', count, code, len(wire), capacity, work)
                        journal.write(header)
                        logical_bytes += len(header)
                        for left, right in zip(before, after, strict=True):
                            journal.write(left)
                            journal.write(right)
                            logical_bytes += len(left) + len(right)
                        require(after[0] == before[0] and after[1][-16:] == b'\xa5'*16
                                and after[2][-16:] == b'\x5a'*16, 'actual borrowed buffers and all guard tails')
                        require(code in (0xffffffff, 0xfffffffe) or 0 <= code <= capacity, 'actual ABI result')
                        body = b'' if code in (0xffffffff, 0xfffffffe) else after[1][:code]
                        stdout.write(f'{code:08x}:'.encode() + body.hex().encode() + b'\n')
                        count += 1
        stdout.flush()
        report.update(status='PASS', calls=count, logical_physical_bytes=logical_bytes,
                      journal=pin(read(output / 'buffers.bin.gz')))
    finally:
        report['completed_calls'] = count
        (output / 'NATIVE.json').write_bytes(encoded(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.manifest.resolve(strict=True), args.output.absolute())
